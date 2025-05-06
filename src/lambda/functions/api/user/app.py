import boto3

# Powertools for AWS Lambda
from aws_lambda_powertools import Logger
from auth_ext.jwt_authenticator import JWTAuthenticator
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.event_handler import (
    APIGatewayRestResolver,
    CORSConfig,
)

# Layer dependencies
from env_config_ext import env_config
from data_validation_ext import ExceptionHandlers
from auth_ext.utils import auth_user, auth_response_set_cookie
from resource_ext.exceptions import ResourceAuthorizationError, ResourceNotFoundError


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
# jwt_encryption_key = parameters.get_parameter(
#     f"/{env_config['ENVIRONMENT']}/auth/creds/jwt-encryption-key", decrypt=True
# )
jwt_authenticator = JWTAuthenticator(
    secret_key=env_config["JWT_ENCRYPTION_KEY"], logger=logger
)


# --------------------------------------------------------------- Validation error handlers
@app.exception_handler(ResourceAuthorizationError)
def handle_unauthorized_error(exc):
    return exception_handlers.unauthorized(exc)


@app.exception_handler(ResourceNotFoundError)
def handle_not_found_error(exc):
    return exception_handlers.not_found(exc)


# --------------------------------------------------------------- API Resources
@app.get("/v1/user")
def retrieve_user():
    # Decode auth access token and retrieve user data
    user = auth_user(
        event=app.current_event,
        jwt_authenticator=jwt_authenticator,
        user_table=db_user_table,
    )

    return auth_response_set_cookie(jwt_authenticator=jwt_authenticator, user=user)


def lambda_handler(event: dict, context: LambdaContext) -> dict:
    return app.resolve(event, context)
