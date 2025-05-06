import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


def exchange_google_code_for_token(code, client_id, client_secret, logger, redirect_uri):
    """
    Exchanges the authorization code for an access token from Google
    with retries and a backoff strategy.

    Args:
        code (str): The authorization code received from Google after user authorization.
        client_id (str): The client ID of your Google OAuth application.
        client_secret (str): The client secret of your Google OAuth application.
        logger (logging.Logger): An instance of logger to log error messages.
        redirect_uri (str): The redirect URI registered with your Google OAuth application.

    Returns:
        str: The access token on success, None otherwise.

    """
    logger.info(f"Google redirect URL: {redirect_uri}")
    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    try:
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            backoff_factor=1,  # A backoff factor to apply between attempts
        )
        # Create an HTTP adapter with the retry strategy and mount it to the session
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()
        session.mount("https://", adapter)

        # Make a request using the session object
        response = session.post(token_url, data=payload)

        # Check response
        if response.ok:
            response_json = response.json()
            logger.info(f"Received response JSON: {response_json}")
            return response_json.get("access_token")
        else:
            logger.error(f"Error exchanging code for access token, status_code={response.status_code}")
            return None
    except Exception as e:
        logger.exception(f"Exception during token exchange: {e}")
        return None


def get_google_user_info(access_token, logger):
    """
    Fetches the Google user's profile information
        using their auth token with retries and backoff strategy.

    Args:
        access_token: The OAuth2 access token of the user.
        logger: logger instance.

    Returns:
        A dictionary containing user profile information on success, None on failure.

    """
    try:
        if not access_token:
            return

        userinfo_endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"

        # Setup retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            backoff_factor=0.5,  # A backoff factor to apply between attempts.
        )
        # Create an HTTP adapter with the retry strategy and mount it to session
        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Create a new session object
        session = requests.Session()
        session.mount("https://", adapter)

        # Make a request using the session object
        response = session.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})

        # Check response
        if response.status_code == 200:
            userdata = response.json()
            logger.info({"Google userdata": userdata})

            return {
                "id": userdata["sub"],
                "name": userdata.get("name"),
                "email": userdata.get("email"),
                "avatar": userdata.get("picture"),
            }
        else:
            logger.error(f"Error fetching user info, status_code={response.status_code}")
    except Exception as e:
        logger.exception(f"FetchUserInfoError: {str(e)}")


def refresh_google_access_token(refresh_token, client_id, client_secret, logger):
    """
    Use Google refresh token to obtain a new auth token with retries and backoff strategy.

    Args:
        refresh_token (str): The refresh token provided by Google's OAuth 2.0.
        client_id (str): The client ID of your application.
        client_secret (str): The client secret of your application.
        logger: logger instance.

    Returns:
        str: The new access token on success, None otherwise.

    """
    try:
        authorization_url = "https://www.googleapis.com/oauth2/v4/token"
        params = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        }

        # Setup retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            backoff_factor=0.5,  # A backoff factor to apply between attempts.
        )
        # Create an HTTP adapter with the retry strategy and mount it to session
        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Create a new session object
        session = requests.Session()
        session.mount("https://", adapter)

        # Make a request using the session object
        response = session.post(authorization_url, data=params)

        # Check response
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            logger.error(f"Error refreshing access token, status_code={response.status_code}")
    except Exception as e:
        logger.exception(f"RefreshAuthTokenError: {str(e)}")
