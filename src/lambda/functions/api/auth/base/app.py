import time
import json
import boto3
import bcrypt
from uuid import uuid4
from typing import Optional

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
from resource_ext import exceptions
from env_config_ext import env_config
from auth_ext.jwt_authenticator import JWTAuthenticator
from data_validation_ext import ExceptionHandlers, PasswordValidator, EmailValidator
from auth_ext.utils import (
    auth_response,
    auth_response_set_cookie,
    get_creds_user_by_email,
    get_db_user,
)

# Lambda dependencies
from utils import github, google


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
# Lambda client
lambda_client = boto3.client("lambda", region_name=env_config["REGION"])

# Define JWT Authenticator
# jwt_encryption_key = parameters.get_parameter(
#     f"/{env_config['ENVIRONMENT']}/auth/creds/jwt-encryption-key", decrypt=True
# )
jwt_authenticator = JWTAuthenticator(
    secret_key=env_config["JWT_ENCRYPTION_KEY"], logger=logger
)

# Google client credentials
google_client_config_str = parameters.get_parameter(
    f"/{env_config['ENVIRONMENT']}/auth/google/client-config", decrypt=True
)
google_client_config = json.loads(google_client_config_str)

# GitHub client credentials
github_client_config_str = parameters.get_parameter(
    f"/{env_config['ENVIRONMENT']}/auth/github/client-config", decrypt=True
)
github_client_config = json.loads(github_client_config_str)


# --------------------------------------------------------------- Pydantic validation Models
class Credentials(BaseModel, EmailValidator, PasswordValidator):
    email: EmailStr
    password: SecretStr


class AuthTokens(BaseModel):
    access_token: Optional[SecretStr] = None
    refresh_token: SecretStr


class AuthCode(BaseModel):
    code: SecretStr


# --------------------------------------------------------------- Validation error handlers
# 400 Bad Request
@app.exception_handler(
    [TypeError, RequestValidationError, ValidationError, ValidationException]
)
def handle_invalid_params_wrapper(exc: RequestValidationError):
    return exception_handlers.invalid_params(exc)


# 401 Unauthorized
@app.exception_handler(exceptions.ResourceAuthorizationError)
def handle_unauthorized_error(exc):
    return exception_handlers.unauthorized(exc)


# 403 Forbidden
@app.exception_handler(exceptions.UnverifiedEmailError)
def handle_forbidden_error(exc):
    return exception_handlers.forbidden(exc)


# 404 NotFound
@app.exception_handler(exceptions.ResourceNotFoundError)
def handle_not_found_error(exc):
    return exception_handlers.not_found(exc)


# 409 Conflict (accountExists)
@app.exception_handler(exceptions.UserAlreadyRegisteredError)
def handle_user_already_registered_wrapper(exc):
    return exception_handlers.conflict(exc)


# --------------------------------------------------------------- Helper functions
def send_email_verification_async(email):
    """
    Sends an email verification link to the provided email address.
    This function asynchronously calls SendVerificationEmailFunction Lambda function.

    Args:
        email (str or EmailStr): The email address to which the verification email will be sent.

    """
    # Define the payload with the email address
    payload = {
        "httpMethod": "POST",
        "path": "/v1/auth/creds/email/send_verification",
        "headers": {
            "Origin": env_config["CORS_ORIGIN_URL"],
        },
        "body": json.dumps({"email": email}),
    }
    # Invoke the Lambda function asynchronously
    lambda_client.invoke(
        FunctionName=f"sla-email-verification-fn-{env_config['ENVIRONMENT']}",
        InvocationType="Event",
        Payload=json.dumps(payload),
    )


# --------------------------------------------------------------- API Resources
@app.post("/v1/auth/session")
def auth_session(auth: AuthTokens):
    if auth.access_token is None:
        # Refresh token is required to generate a new access token
        access_token = jwt_authenticator.refresh_access_token(
            refresh_token=auth.refresh_token.get_secret_value(),
            get_user_fn=lambda user_id: get_db_user(
                user_table=db_user_table,
                user_id=user_id,
            ),
        )
    else:
        access_token = auth.access_token.get_secret_value()

    user = jwt_authenticator.decode_token(token=access_token)
    logger.info({"decoded_data": user})

    if user is None:
        raise exceptions.ResourceAuthorizationError

    return auth_response(jwt_authenticator=jwt_authenticator, user=user)


@app.post("/v1/auth/creds/sign_up")
def creds_sign_up(creds: Credentials):
    # Check if user already registered
    creds_user = get_creds_user_by_email(user_table=db_user_table, email=creds.email)

    if creds_user:
        raise exceptions.UserAlreadyRegisteredError

    # Save user to the database
    user_id = f"user_creds_{uuid4().hex}"
    created_at = int(time.time())
    user = {
        "id": user_id,
        "provider": "creds",
        "email": creds.email,
        "email_verified": True,  # TODO: Set to False for email verification
        "password": bcrypt.hashpw(
            creds.password.get_secret_value().encode(),
            env_config["BCRYPT_SALT"].encode(),
        ),
        "password_verified": True,
        "created_at": created_at,
        "updated_at": created_at,
    }
    db_user_table.put_item(Item=user)

    send_email_verification_async(email=creds.email)
    return Response(status_code=200)


@app.post("/v1/auth/creds/log_in")
def creds_log_in(creds: Credentials):
    # Retrieve creds user (user registered with email/password) from the database
    logger.info(f"Fetching user by email: {creds.email}")
    user = get_creds_user_by_email(user_table=db_user_table, email=creds.email)

    if user is None:
        raise exceptions.ResourceAuthorizationError

    # Check user password
    password_matches = bcrypt.checkpw(
        creds.password.get_secret_value().encode(), user["password"].value
    )

    if user.get("password_verified", False) is False or not password_matches:
        logger.warning(f"Invalid password for user: {user['id']}")
        raise exceptions.ResourceAuthorizationError

    if not user.get("email_verified", False):
        raise exceptions.UnverifiedEmailError

    # Update the 'updated_at' attribute - update last log-in time
    updated_at = int(time.time())
    db_user_table.update_item(
        Key={"id": user["id"]},
        UpdateExpression="SET updated_at = :val",
        ExpressionAttributeValues={":val": int(time.time())},
    )
    user["updated_at"] = updated_at

    return auth_response_set_cookie(jwt_authenticator=jwt_authenticator, user=user)


@app.post("/v1/auth/sso/<provider>/sign_up")
def sso_sign_up(provider: str, auth: AuthCode):
    logger.info({"access_token": auth.code.get_secret_value()})

    # Fetch user data from SSO provider using OAuth2
    if provider == "google":
        access_token = google.exchange_google_code_for_token(
            code=auth.code.get_secret_value(),
            client_id=google_client_config["web"]["client_id"],
            client_secret=google_client_config["web"]["client_secret"],
            redirect_uri=f"{env_config['CORS_ORIGIN_URL']}/api/auth/callback/google?type=sign_up",
            logger=logger,
        )
        user_info = google.get_google_user_info(
            access_token=access_token, logger=logger
        )
    elif provider == "github":
        access_token = github.exchange_github_code_for_token(
            code=auth.code.get_secret_value(),
            client_id=github_client_config["client_id"],
            client_secret=github_client_config["client_secret"],
            logger=logger,
        )
        user_info = github.get_github_user_info(
            access_token=access_token, logger=logger
        )
    else:
        raise ValidationException(
            errors=[
                {
                    "loc": ("path", "provider"),
                    "msg": f"Unsupported SSO provider: {provider}",
                }
            ]
        )

    if user_info is None:
        raise exceptions.ResourceAuthorizationError

    # Check if user already registered
    user_id = f"user_{provider}_{user_info['id']}"
    user = get_db_user(user_table=db_user_table, user_id=user_id)

    if user:
        raise exceptions.UserAlreadyRegisteredError

    # Save user to the database
    created_at = int(time.time())
    user = {
        "id": user_id,
        "provider": provider,
        "email_verified": True,
        "name": user_info.get("name"),
        "email": user_info.get("email"),
        "avatar": user_info.get("avatar"),
        "created_at": created_at,
        "updated_at": created_at,
    }
    db_user_table.put_item(Item=user)

    return auth_response(jwt_authenticator=jwt_authenticator, user=user)


@app.post("/v1/auth/sso/<provider>/log_in")
def sso_log_in(provider: str, auth: AuthCode):
    logger.info({"access_token": auth.code.get_secret_value()})

    # Fetch user data from the SSO provider using OAuth2
    if provider == "google":
        access_token = google.exchange_google_code_for_token(
            code=auth.code.get_secret_value(),
            client_id=google_client_config["web"]["client_id"],
            client_secret=google_client_config["web"]["client_secret"],
            redirect_uri=f"{env_config['CORS_ORIGIN_URL']}/api/auth/callback/google?type=sign_in",
            logger=logger,
        )
        user_info = google.get_google_user_info(
            access_token=access_token, logger=logger
        )
    elif provider == "github":
        access_token = github.exchange_github_code_for_token(
            code=auth.code.get_secret_value(),
            client_id=github_client_config["client_id"],
            client_secret=github_client_config["client_secret"],
            logger=logger,
        )
        user_info = github.get_github_user_info(
            access_token=access_token, logger=logger
        )
    else:
        raise ValidationException(
            errors=[
                {
                    "loc": ("path", "provider"),
                    "msg": f"Unsupported SSO provider: {provider}",
                }
            ]
        )

    if user_info is None:
        raise exceptions.ResourceAuthorizationError

    try:
        user_id = f"user_{provider}_{user_info['id']}"
        # Attempt to update the 'updated_at' attribute, expecting the item to exist
        response = db_user_table.update_item(
            Key={"id": user_id},
            UpdateExpression="SET updated_at = :val",
            ExpressionAttributeValues={":val": int(time.time())},
            ConditionExpression="attribute_exists(id)",
            ReturnValues="ALL_NEW",  # Returns all attributes of the item after the update
        )

        # If the item was successfully updated, retrieve the updated item data from the response
        user = response.get("Attributes")

    except db_user_table.meta.client.exceptions.ConditionalCheckFailedException:
        raise exceptions.ResourceAuthorizationError

    return auth_response(jwt_authenticator=jwt_authenticator, user=user)


def lambda_handler(event: dict, context: LambdaContext) -> dict:
    return app.resolve(event, context)
