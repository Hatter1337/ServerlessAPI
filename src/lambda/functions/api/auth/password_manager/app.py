import boto3
from datetime import datetime, UTC

# Powertools for AWS Lambda
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities import parameters
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.shared.cookies import Cookie, SameSite
from aws_lambda_powertools.event_handler import (
    APIGatewayRestResolver,
    Response,
    CORSConfig,
)
from aws_lambda_powertools.event_handler.openapi.exceptions import (
    RequestValidationError,
    ValidationException,
)
from pydantic import BaseModel, EmailStr, SecretStr, ValidationError

# Layer dependencies
from env_config_ext import env_config
from auth_ext.encryptor import KMSEncryptor
from auth_ext.utils import parse_cookie_header
from auth_ext.jwt_authenticator import JWTAuthenticator
from resource_ext.exceptions import ResourceNotFoundError
from resource_ext.exceptions import ResourceAuthorizationError
from data_validation_ext import ExceptionHandlers, EmailValidator
from auth_ext.utils import (
    auth_user,
    auth_response,
    auth_response_set_cookie,
    get_creds_user_by_email,
)
from notifications_ext import (
    EmailNotifier,
    EmailTokenManager,
    EmailNotifierLimitExceededError,
    EmailNotifierDeliveryError,
)


# --------------------------------------------------------------- Application & clients
cors_config = CORSConfig(
    allow_origin=env_config["CORS_ORIGIN_URL"],
    allow_headers=env_config["ALLOW_HEADERS"],
    allow_credentials=True,
)
app = APIGatewayRestResolver(cors=cors_config, enable_validation=True)

logger = Logger()
exception_handlers = ExceptionHandlers(app=app, logger=logger)

# DynamoDB's resource for auth-users table
resource = boto3.resource("dynamodb")
db_user_table = resource.Table(f"sla-user-{env_config['ENVIRONMENT']}")

# Define EmailTokenManager & EmailNotifier
email_token_encryption_key = parameters.get_parameter(
    f"/{env_config['ENVIRONMENT']}/auth/creds/email-token-encryption-key", decrypt=True
)
email_token_manager = EmailTokenManager(
    secret_key=email_token_encryption_key, logger=logger
)
email_notifier = EmailNotifier(logger=logger)

# Define Password Encryptor & JWT Authenticator
pwd_encryptor = KMSEncryptor(kms_key_arn=env_config["KMS_ENCRYPTION_KEY"])
jwt_encryption_key = parameters.get_parameter(
    f"/{env_config['ENVIRONMENT']}/auth/creds/jwt-encryption-key", decrypt=True
)
jwt_authenticator = JWTAuthenticator(secret_key=jwt_encryption_key, logger=logger)


# --------------------------------------------------------------- Pydantic validation Models
class PasswordChangeParams(BaseModel):
    old_password: SecretStr
    new_password: SecretStr


class PasswordResetParams(BaseModel, EmailValidator):
    email: EmailStr


class PasswordSetParams(BaseModel):
    password: SecretStr


class PasswordCreateParams(BaseModel):
    password: SecretStr


class PasswordConfirmParams(BaseModel):
    code: str


# --------------------------------------------------------------- Validation error handlers
# 400 Bad Request
@app.exception_handler(
    [TypeError, RequestValidationError, ValidationError, ValidationException]
)
def handle_invalid_params_wrapper(exc: RequestValidationError):
    return exception_handlers.invalid_params(exc)


# 401 Unauthorized
@app.exception_handler(ResourceAuthorizationError)
def handle_unauthorized_error(exc):
    return exception_handlers.unauthorized(exc)


# 404 NotFound
@app.exception_handler(ResourceNotFoundError)
def handle_not_found_error(exc):
    return exception_handlers.not_found(exc)


# 424 Failed Dependency (emailWasNotSent) & 429 Too Many Requests (emailRateLimitExceeded)
@app.exception_handler([EmailNotifierLimitExceededError, EmailNotifierDeliveryError])
def handle_email_notifier_wrapper(exc):
    return exception_handlers.email_notifier(exc)


# --------------------------------------------------------------- API Resources
@app.post("/v1/auth/creds/password/reset")
def password_reset(body: PasswordResetParams):
    """
    Initiates the password reset process for the user associated with the provided email address.

    The reset link includes the token as a query parameter,
        allowing the user to securely update their password.

    """
    user = get_creds_user_by_email(user_table=db_user_table, email=body.email)

    if user is None:
        raise ResourceNotFoundError

    email_token = email_token_manager.generate_token(
        email=body.email, token_type="password_reset"
    )
    email_notifier.send_forgot_password_email(
        recipient_email=body.email,
        reset_link=f"{env_config['CORS_ORIGIN_URL']}/api/auth/reset-password?code={email_token}",
    )

    return Response(status_code=200)


@app.post("/v1/auth/creds/password/set")
def password_set(body: PasswordSetParams):
    # retrieve 'code' from cookies
    cookie_header = app.current_event.headers.get("Cookie")
    cookies = parse_cookie_header(cookie_header, logger=logger)

    # verification email token
    valid, payload = email_token_manager.verify_token(
        cookies.get("password_reset_code")
    )

    if not valid:
        raise ValidationException(
            errors=[
                {
                    "loc": ("cookie", "password_reset_code"),
                    "msg": "Invalid or expired code",
                }
            ]
        )

    # Retrieve and verification user
    user = get_creds_user_by_email(user_table=db_user_table, email=payload["email"])

    if user is None:
        raise ResourceNotFoundError

    # Update user password to new value
    response = db_user_table.update_item(
        Key={"id": user["id"]},
        UpdateExpression="SET password = :val",
        ExpressionAttributeValues={
            ":val": pwd_encryptor.encrypt(body.password.get_secret_value())
        },
        ReturnValues="ALL_NEW",
    )
    user = response.get("Attributes")

    now = datetime.now(UTC)
    return auth_response_set_cookie(
        jwt_authenticator=jwt_authenticator,
        user=user,
        extra_cookies=[
            Cookie(
                path="/",
                http_only=True,
                name="password_reset_code",
                same_site=SameSite.LAX_MODE,
                value="",
                expires=now,
            )
        ],
    )


@app.post("/v1/auth/creds/password/change")
def password_change(body: PasswordChangeParams):
    # Decode auth access token and retrieve user data
    user = auth_user(
        event=app.current_event,
        jwt_authenticator=jwt_authenticator,
        user_table=db_user_table,
    )

    # Compare provided password with password from DB
    if pwd_encryptor.decrypt(user["password"]) != body.old_password.get_secret_value():
        logger.info(f"Wrong password, user_id={user['id']}")
        raise ResourceAuthorizationError

    # Update password in DB to the new value
    try:
        response = db_user_table.update_item(
            Key={"id": user["id"]},
            UpdateExpression="SET password = :val",
            ExpressionAttributeValues={
                ":val": pwd_encryptor.encrypt(body.new_password.get_secret_value())
            },
            ConditionExpression="attribute_exists(id)",
            ReturnValues="ALL_NEW",
        )
        user = response.get("Attributes")
    except db_user_table.meta.client.exceptions.ConditionalCheckFailedException:
        raise ResourceNotFoundError

    return auth_response_set_cookie(jwt_authenticator=jwt_authenticator, user=user)


@app.post("/v1/auth/creds/password/create")
def password_create(body: PasswordCreateParams):
    # Decode auth access token and retrieve user data
    user = auth_user(
        event=app.current_event,
        jwt_authenticator=jwt_authenticator,
        user_table=db_user_table,
    )

    # Create password (for user registered via a magic link)
    try:
        logger.info(f"Create password for user: {user['id']}")
        response = db_user_table.update_item(
            Key={"id": user["id"]},
            UpdateExpression="SET password = :val",
            ExpressionAttributeValues={
                ":val": pwd_encryptor.encrypt(body.password.get_secret_value())
            },
            ConditionExpression="attribute_exists(id)",
            ReturnValues="ALL_NEW",
        )
        user = response.get("Attributes")
    except db_user_table.meta.client.exceptions.ConditionalCheckFailedException:
        raise ResourceNotFoundError

    # Send password confirmation email
    email_token = email_token_manager.generate_token(
        email=user["email"],
        token_type="password_confirm",
    )
    verification_link = (
        f"{env_config['CORS_ORIGIN_URL']}/api/auth/confirm-password?code={email_token}"
    )
    email_notifier.send_password_confirmation_email(
        recipient_email=user["email"],
        verification_link=verification_link,
    )

    return auth_response_set_cookie(jwt_authenticator=jwt_authenticator, user=user)


@app.post("/v1/auth/creds/password/confirm")
def password_confirm(body: PasswordConfirmParams):
    # verification email token
    valid, payload = email_token_manager.verify_token(body.code)

    if not valid:
        raise ValidationException(
            errors=[{"loc": ("body", "code"), "msg": "Invalid or expired code"}]
        )

    # Retrieve and verification user
    user = get_creds_user_by_email(user_table=db_user_table, email=payload["email"])

    if user is None:
        raise ResourceNotFoundError

    # Confirm the created password (for user registered via magic link)
    try:
        response = db_user_table.update_item(
            Key={"id": user["id"]},
            UpdateExpression="SET password_verified = :val",
            ExpressionAttributeValues={":val": True},
            ConditionExpression="attribute_exists(id)",
            ReturnValues="ALL_NEW",
        )
        user = response.get("Attributes")
    except db_user_table.meta.client.exceptions.ConditionalCheckFailedException:
        raise ResourceNotFoundError

    return auth_response(jwt_authenticator=jwt_authenticator, user=user)


def lambda_handler(event: dict, context: LambdaContext) -> dict:
    return app.resolve(event, context)
