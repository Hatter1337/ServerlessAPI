from http import HTTPStatus
from datetime import datetime, UTC

from aws_lambda_powertools.shared.cookies import Cookie, SameSite
from aws_lambda_powertools.event_handler import Response, content_types

from data_validation_ext.helper import validation_error_description


class ExceptionHandlers:
    """
    Class to handle common exceptions for AWS Lambda functions using AWS Lambda Powertools.

    Attributes:
        app (LambdaPowertoolsApp): An instance of the LambdaPowertoolsApp.
        logger (Logger): An instance of the Powertools Logger.

    """

    def __init__(self, app, logger):
        self.app = app
        self.logger = logger

    # 400 Bad Request
    def invalid_params(self, exc):
        """
        Handles RequestValidationError exceptions
            by logging the error and returning a custom Response.

        Args:
            exc (RequestValidationError): The exception object.

        Returns:
            Response: A custom response with a status code of 400, indicating a bad request.

        """
        if exc.__class__.__name__ == "TypeError" and "JSON object must be" in str(exc):
            error_description = {"body": "Invalid or empty request body"}
        else:
            # error_description = validation_error_description(exc)  # TODO: Fix if needed
            error_description = str(exc)
            self.logger.error(
                f"Data validation error: {error_description}",
                extra={
                    "path": self.app.current_event.path,
                    "query_strings": self.app.current_event.query_string_parameters,
                },
            )

        return Response(
            status_code=HTTPStatus.BAD_REQUEST.value,
            content_type=content_types.APPLICATION_JSON,
            body={
                "error": {
                    "code": f"ERR_{HTTPStatus.BAD_REQUEST.name}",
                    "message": "common.apiErrors.badRequest",
                    "description": error_description,
                }
            },
        )

    # 401 Unauthorized
    @staticmethod
    def unauthorized(exc):  # noqa
        """
        Handles unauthorized access exceptions by returning a custom Response.

        Args:
            exc (Exception): The exception object.

        Returns:
            Response: A custom response with a status code of 401,
                indicating unauthorized access.

        """
        now = datetime.now(UTC)
        return Response(
            status_code=HTTPStatus.UNAUTHORIZED.value,
            content_type=content_types.APPLICATION_JSON,
            body={
                "error": {
                    "code": f"ERR_{HTTPStatus.UNAUTHORIZED.name}",
                    "message": "common.apiErrors.unauthorized",
                }
            },
            cookies=[
                Cookie(
                    path="/",
                    http_only=True,
                    name="access_token",
                    same_site=SameSite.LAX_MODE,
                    value="",
                    expires=now,
                ),
                Cookie(
                    path="/",
                    http_only=True,
                    name="refresh_token",
                    same_site=SameSite.LAX_MODE,
                    value="",
                    expires=now,
                ),
                Cookie(
                    path="/",
                    http_only=True,
                    name="access_token_expires_in",
                    same_site=SameSite.LAX_MODE,
                    value="",
                    expires=now,
                ),
                Cookie(
                    path="/",
                    http_only=True,
                    name="refresh_token_expires_in",
                    same_site=SameSite.LAX_MODE,
                    value="",
                    expires=now,
                ),
            ],
        )

    # 403 Forbidden
    @staticmethod
    def forbidden(exc):  # noqa
        """
        Handles resource not forbidden by returning a custom Response.

        Args:
            exc (Exception): The exception object.

        Returns:
            Response: A custom response with a status code of 403,
                indicating that user not having the necessary permissions.

        """
        if exc.__class__.__name__ == "UnverifiedEmailError":
            return Response(
                status_code=HTTPStatus.FORBIDDEN.value,
                content_type=content_types.APPLICATION_JSON,
                body={
                    "error": {
                        "code": f"ERR_{HTTPStatus.FORBIDDEN.name}",
                        "message": "common.apiErrors.unverifiedEmail",
                    }
                },
            )
        return Response(
            status_code=HTTPStatus.FORBIDDEN.value,
            content_type=content_types.APPLICATION_JSON,
            body={
                "error": {
                    "code": f"ERR_{HTTPStatus.FORBIDDEN.name}",
                    "message": "common.apiErrors.accessDenied",
                }
            },
        )

    # 404 Not Found
    @staticmethod
    def not_found(exc):  # noqa
        """
        Handles resource not found exceptions by returning a custom Response.

        Args:
            exc (Exception): The exception object.

        Returns:
            Response: A custom response with a status code of 404,
                indicating that the resource was not found.

        """
        return Response(
            status_code=HTTPStatus.NOT_FOUND.value,
            content_type=content_types.APPLICATION_JSON,
            body={
                "error": {
                    "code": f"ERR_{HTTPStatus.NOT_FOUND.name}",
                    "message": "common.apiErrors.notFound",
                }
            },
        )

    # 409 Conflict (accountExists)
    @staticmethod
    def conflict(exc):  # noqa
        """
        Handles resource conflict exceptions by returning a custom Response.

        Args:
            exc (Exception): The exception object.

        Returns:
            Response: A custom response with a status code of 409,
                indicating that a data conflict has occurred.

        """
        error_message_mapping = {
            "UserAlreadyRegisteredError": "accountExists",
            "UserAlreadySubscribedError": "subscriptionExists",
        }
        message = error_message_mapping.get(exc.__class__.__name__, "conflict")

        return Response(
            status_code=HTTPStatus.CONFLICT.value,
            content_type=content_types.APPLICATION_JSON,
            body={
                "error": {
                    "code": f"ERR_{HTTPStatus.CONFLICT.name}",
                    "message": f"common.apiErrors.{message}",
                }
            },
        )

    # 424 Failed Dependency (emailWasNotSent) & 429 Too Many Requests (emailRateLimitExceeded)
    @staticmethod
    def email_notifier(exc):
        """
        Handles EmailNotifier exceptions by returning a custom Response.

        Args:
            exc: The exception object.

        Returns:
            Response: A custom response with a status codes of:
                - 429 (TOO_MANY_REQUESTS) indicating that the email rate limit exceeded;
                - 424 (FAILED_DEPENDENCY) indicating that the email wasn't sent.

        """
        if (
            exc.__class__.__name__ == "EmailNotifierLimitExceededError"
        ):  # 429 Too Many Requests
            return Response(
                status_code=HTTPStatus.TOO_MANY_REQUESTS.value,
                content_type=content_types.APPLICATION_JSON,
                body={
                    "error": {
                        "code": f"ERR_{HTTPStatus.TOO_MANY_REQUESTS.name}",
                        "message": "common.apiErrors.emailRateLimitExceeded",
                        "description": {
                            "rule": exc.rule,
                            "retry_after": exc.retry_after,
                        },
                    }
                },
            )
        # EmailNotifierDeliveryError -> # 424 Failed Dependency
        return Response(
            status_code=HTTPStatus.FAILED_DEPENDENCY.value,
            content_type=content_types.APPLICATION_JSON,
            body={
                "error": {
                    "code": f"ERR_{HTTPStatus.FAILED_DEPENDENCY.name}",
                    "message": "common.apiErrors.emailWasNotSent",
                }
            },
        )
