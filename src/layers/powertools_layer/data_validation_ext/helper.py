from aws_lambda_powertools.event_handler.openapi.exceptions import RequestValidationError


def validation_error_description(exc: RequestValidationError):
    """
    Extracts and formats validation error messages from a RequestValidationError.
    It creates a dictionary where each key represents the location of the validation error
    in the request (e.g., "body.email"), and the corresponding value is the error message.

    Args:
        exc (RequestValidationError): The exception raised during request validation.

    Returns:
        dict: A dictionary containing detailed descriptions of each validation error.

    """
    error_description = {}

    for error in exc.errors():
        # Creating a string representation of the location (path) of each error in the request
        field = ".".join([str(elem) for elem in error["loc"]])
        # Mapping the error location to its message
        error_description[field] = error["msg"]

    return error_description
