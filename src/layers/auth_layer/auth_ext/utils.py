import secrets
from urllib import parse
from boto3.dynamodb.conditions import Key

from aws_lambda_powertools import Logger
from aws_lambda_powertools.event_handler import Response
from aws_lambda_powertools.event_handler import content_types
from aws_lambda_powertools.shared.cookies import Cookie, SameSite

from resource_ext.exceptions import ResourceAuthorizationError, ResourceNotFoundError

logger = Logger()


def generate_api_key():
    """
    Generates a secure, random API key.

    This function uses the secrets module to generate a URL-safe, random string
    that can be used as a secure API key. The length of the generated string is
    32 characters, which provides a good balance between security and usability.

    Returns:
        str: A URL-safe, random string suitable for use as an API key.

    """
    # Generate a secure random string of 32 characters.
    # You can adjust the length by changing the argument of token_urlsafe.
    return secrets.token_urlsafe(32)


def parse_cookie_header(cookie_header, logger=None):
    """
    Parses a cookie header string into a dictionary of cookies.

    This function takes a cookie header string, typically found in HTTP request
        headers, and parses it into a dictionary where each cookie name is a key,
        and its corresponding value is the value.
    The cookie names are converted to lowercase to ensure case-insensitive matching.

    Parameters:
        cookie_header (str): The cookie header string to be parsed. This is
            usually the value of the 'Cookie' header in an HTTP request.
        logger (logging.Logger, optional): An optional logger object to log exceptions
            if parsing fails. Defaults to None, in which case exceptions are not logged.

    Returns:
        dict: A dictionary where each key-value pair represents a cookie name and its value.
        Cookie names are converted to lowercase.

    Example:
        cookie_header = "UserID=JohnDoe; Max-Age=3600; Path=/"
        cookies = parse_cookie_header(cookie_header)
        print(cookies)  # Output: {'userid': 'JohnDoe', 'max-age': '3600', 'path': '/'}

    """
    cookies = {}

    if cookie_header:
        try:
            for cookie in cookie_header.split("; "):
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    cookies[key.lower()] = parse.unquote(value)
        except Exception as e:
            if logger:
                logger.exception(f"Parse cookie, error: {str(e)}")

    return cookies


def get_db_user(user_table, user_id):
    """
    Retrieve User from the database by ID.

    Args:
        user_table: DynamoDB table resource.
        user_id (str): User ID.

    Returns:
        dict: User data if the user with the specified ID exists, otherwise None.

    """
    response = user_table.get_item(Key={"id": user_id})
    return response.get("Item")


def get_creds_user_by_email(user_table, email):
    """
    Retrieve User from the database by email.
    This function returns only user registered with email/password.

    Args:
        user_table: DynamoDB Resource table for User.
        email (str or EmailStr): User email.

    Returns:
        dict: User data if the user with the specified email address exists, otherwise None.

    """
    query_response = user_table.query(
        IndexName="email_index",
        KeyConditionExpression=Key("email").eq(email)
        & Key("id").begins_with("user_creds_"),
    )
    return query_response["Items"][0] if query_response["Items"] else None


def hide_user_sensitive_data(user):
    """
    Hide sensitive data, like 'email', 'password' before response.

    Args:
        user (dict): User data.

    Returns:
        dict: safe User data.

    """
    # clear sensitive attrs
    user.pop("email", None)
    user.pop("api_key", None)

    # set attr 'password_created'
    password = user.pop("password", None)
    user["password_created"] = bool(password)

    return user


def hide_email(email):
    """
    Hides an email address by keeping the first 3 characters visible and replacing
    the rest with asterisks up to the '@' character.

    Args:
        email (str or EmailStr): The email address to be hidden.

    Returns:
        str: The email address with the characters hidden, except for the first 3 characters
             and the domain part of the email.

    Example:
        > hide_email("example@gmail.com")
        'exa****@gmail.com'
    """
    # Find the index of the '@' character
    at_index = email.find("@")

    # Keep the first 3 characters and replace the rest up to the '@' with asterisks
    return email[:3] + "*" * (at_index - 3) + email[at_index:]


def auth_user_id(event, jwt_authenticator, logger):
    """
    Authenticates a user by their access token found in the event's cookie header.

    This function extracts the 'access_token' from the cookies in the incoming request's
        'Cookie' header, decodes the token to verification the user's identity, and returns the user's ID.

    Args:
        event: The event object that includes the request details.
        jwt_authenticator: The JWT authenticator instance used for decoding the access token.
        logger: Logger instance for logging the process.

    Returns:
        str: The authenticated user's ID if the token is valid.

    Raises:
        ResourceAuthorizationError: If the access token is missing, invalid,
            or if the decoded data does not contain a user ID.

    """
    cookie_header = event.get_header_value(name="Cookie", case_sensitive=False)
    cookies = parse_cookie_header(cookie_header, logger=logger)

    if cookies.get("access_token") is None:
        raise ResourceAuthorizationError

    decoded_data = jwt_authenticator.decode_token(token=cookies["access_token"])

    if decoded_data is None or decoded_data.get("id") is None:
        raise ResourceAuthorizationError

    return decoded_data.get("id")


def auth_user(event, jwt_authenticator, user_table):
    """
    Authenticates a user based on the access token provided in cookies.

    This function retrieves the 'Cookie' header from the incoming event, parses the cookies
        to extract the access token, and decodes the token to authenticate the user.
    If the authentication is successful, it fetches the user's data from the DynamoDB table.

    Args:
        event: The event object containing the request details.
        jwt_authenticator: An object capable of decoding JWT tokens.
        user_table: A reference to the DynamoDB table where user data is stored.

    Returns:
        dict: The authenticated user's data if the authentication is successful.

    Raises:
        ResourceAuthorizationError: If the access token is missing
            or if the decoded data does not contain a valid user ID.

    """
    cookie_header = event.get_header_value(name="Cookie", case_sensitive=False)
    cookies = parse_cookie_header(cookie_header, logger=logger)

    if cookies.get("access_token") is None:
        raise ResourceAuthorizationError

    decoded_data = jwt_authenticator.decode_token(token=cookies["access_token"])
    logger.info({"decoded_data": decoded_data})

    if decoded_data is None or decoded_data.get("id") is None:
        raise ResourceAuthorizationError

    response = user_table.get_item(Key={"id": decoded_data["id"]})
    user = response.get("Item")

    if user is None:
        raise ResourceNotFoundError

    return user


def dt2cookie_format(value):
    """
    Converts a datetime object to a string format suitable for cookies.

    This function takes a datetime object and converts it into a string in the
        ISO 8601 format, with milliseconds precision.
    The '+00:00' timezone information is replaced with 'Z' to denote UTC time,
        making it suitable for use in cookies.

    Args:
        value (datetime.datetime): The datetime object to be converted.

    Returns:
        str: The formatted datetime string suitable for cookies.

    """
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def auth_response(jwt_authenticator, user):
    # Generate auth tokens
    tokens = jwt_authenticator.create_tokens(
        user_data={
            "id": user["id"],
            "name": user.get("name"),
            "email": user.get("email"),
        }
    )

    return Response(
        status_code=200,
        content_type=content_types.APPLICATION_JSON,
        body={
            "user": hide_user_sensitive_data(user=user),
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "access_token_expires_in": dt2cookie_format(
                tokens["access_token_expires_in"]
            ),
            "refresh_token_expires_in": dt2cookie_format(
                tokens["refresh_token_expires_in"]
            ),
        },
    )


def auth_response_set_cookie(jwt_authenticator, user, extra_cookies=None):
    # Generate auth tokens
    tokens = jwt_authenticator.create_tokens(
        user_data={
            "id": user["id"],
            "name": user.get("name"),
            "email": user.get("email"),
        }
    )

    cookies = [
        Cookie(
            path="/",
            http_only=True,
            name="access_token",
            same_site=SameSite.LAX_MODE,
            value=tokens["access_token"],
            expires=tokens["access_token_expires_in"],
        ),
        Cookie(
            path="/",
            http_only=True,
            name="refresh_token",
            same_site=SameSite.LAX_MODE,
            value=tokens["refresh_token"],
            expires=tokens["refresh_token_expires_in"],
        ),
        Cookie(
            path="/",
            http_only=True,
            name="access_token_expires_in",
            same_site=SameSite.LAX_MODE,
            value=dt2cookie_format(tokens["access_token_expires_in"]),
            expires=tokens["access_token_expires_in"],
        ),
        Cookie(
            path="/",
            http_only=True,
            name="refresh_token_expires_in",
            same_site=SameSite.LAX_MODE,
            value=dt2cookie_format(tokens["refresh_token_expires_in"]),
            expires=tokens["refresh_token_expires_in"],
        ),
    ]

    if extra_cookies:
        cookies.extend(extra_cookies)

    return Response(
        status_code=200,
        content_type=content_types.APPLICATION_JSON,
        body={
            "user": hide_user_sensitive_data(user=user),
        },
        cookies=cookies,
    )
