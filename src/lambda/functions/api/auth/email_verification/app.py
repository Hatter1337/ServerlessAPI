import boto3

# Powertools for AWS Lambda
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities import parameters
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.event_handler import (
    APIGatewayRestResolver,
    Response,
    CORSConfig,
)
from aws_lambda_powertools.event_handler.openapi.exceptions import (
    RequestValidationError,
    ValidationException,
)
from pydantic import BaseModel, SecretStr, EmailStr, ValidationError

# Layer dependencies
from env_config_ext import env_config
from auth_ext.jwt_authenticator import JWTAuthenticator
from resource_ext.exceptions import ResourceNotFoundError
from data_validation_ext import ExceptionHandlers, EmailValidator
from auth_ext.utils import auth_response, get_creds_user_by_email, hide_email
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

# Define JWT Authenticator
jwt_encryption_key = parameters.get_parameter(
    f"/{env_config['ENVIRONMENT']}/auth/creds/jwt-encryption-key", decrypt=True
)
jwt_authenticator = JWTAuthenticator(secret_key=jwt_encryption_key, logger=logger)

# Define EmailTokenManager & EmailNotifier
email_token_encryption_key = parameters.get_parameter(
    f"/{env_config['ENVIRONMENT']}/auth/creds/email-token-encryption-key", decrypt=True
)
email_token_manager = EmailTokenManager(
    secret_key=email_token_encryption_key, logger=logger
)
email_notifier = EmailNotifier(logger=logger)


# --------------------------------------------------------------- Pydantic validation Models
class Credentials(BaseModel, EmailValidator):
    email: EmailStr


class AuthCode(BaseModel):
    code: SecretStr


# --------------------------------------------------------------- Validation error handlers
# 400 Bad Request
@app.exception_handler(
    [TypeError, RequestValidationError, ValidationError, ValidationException]
)
def handle_invalid_params_wrapper(exc: RequestValidationError):
    return exception_handlers.invalid_params(exc)


# 404 NotFound
@app.exception_handler(ResourceNotFoundError)
def handle_not_found_error(exc):
    return exception_handlers.not_found(exc)


# 424 Failed Dependency (emailWasNotSent) & 429 Too Many Requests (emailRateLimitExceeded)
@app.exception_handler([EmailNotifierLimitExceededError, EmailNotifierDeliveryError])
def handle_email_notifier_wrapper(exc):
    return exception_handlers.email_notifier(exc)


# --------------------------------------------------------------- API Resources
@app.post("/v1/auth/creds/email/send_verification")
def send_verification_email(creds: Credentials):
    """
    Sends an email verification link to the provided email address.

    This function generates an email verification token and sends an email to the specified email
        containing a verification link.
    The link includes the token as a query parameter.

    """
    origin: str = app.current_event.headers.get("Origin", env_config["CORS_ORIGIN_URL"])

    email_token = email_token_manager.generate_token(
        email=creds.email, token_type="sign_up"
    )
    verification_link = f"{origin}/api/auth/confirm-email?code={email_token}"

    logger.info(
        f"Send verification email, email={hide_email(creds.email)}, {verification_link=}"
    )
    email_notifier.send_verification_email(
        recipient_email=creds.email,
        verification_link=verification_link,
    )

    return Response(status_code=200)


@app.post("/v1/auth/creds/email/confirm")
def confirm_email(auth: AuthCode):
    # verification email token
    valid, payload = email_token_manager.verify_token(
        token=auth.code.get_secret_value()
    )

    if not valid:
        raise ValidationException(
            errors=[{"loc": ("body", "code"), "msg": "Invalid or expired code"}]
        )

    # Retrieve and verification user
    user = get_creds_user_by_email(user_table=db_user_table, email=payload["email"])

    if user is None:
        logger.info(
            f"Confirm email, user with email={hide_email(payload['email'])} not found"
        )
        raise ResourceNotFoundError

    # Update attr 'email_verified' to True
    response = db_user_table.update_item(
        Key={"id": user["id"]},
        UpdateExpression="SET email_verified = :val",
        ExpressionAttributeValues={":val": True},
        ReturnValues="ALL_NEW",
    )
    user = response.get("Attributes")

    return auth_response(jwt_authenticator=jwt_authenticator, user=user)


def lambda_handler(event: dict, context: LambdaContext) -> dict:
    return app.resolve(event, context)
