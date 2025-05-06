import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


def exchange_github_code_for_token(code, client_id, client_secret, logger):
    """
    Exchanges the authorization code for an access token from GitHub
        with retries and a backoff strategy.

    Args:
        code (str): The authorization code received from GitHub after user authorization.
        client_id (str): The client ID of your GitHub OAuth application.
        client_secret (str): The client secret of your GitHub OAuth application.
        logger (logging.Logger): An instance of logger to log error messages.

    Returns:
        str: The access token on success, None otherwise.

    """
    token_url = "https://github.com/login/oauth/access_token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
    }
    headers = {"Accept": "application/json"}

    try:
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            backoff_factor=1,  # A backoff factor to apply between attempts
        )
        # Create an HTTP adapter with the retry strategy and mount it to the session
        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Create a new session object
        session = requests.Session()
        session.mount("https://", adapter)

        # Make a request using the session object
        response = session.post(token_url, data=payload, headers=headers)

        # Check response
        if response.ok:
            access_token = response.json().get("access_token")
            return access_token
        else:
            logger.error(f"Error exchanging code for access token, status_code={response.status_code}")
            return None
    except Exception as e:
        logger.exception(f"ExchangeCodeForTokenError: {str(e)}")
        return None


def get_github_user_info(access_token, logger):
    """
    Fetches the GitHub user's profile information and email
        using their auth token with retries and a backoff strategy.

    Args:
        access_token (str): The OAuth2 access token of the user.
        logger (logging.Logger): An instance of logger to log error messages.

    Returns:
        dict: A dictionary containing user profile information and email on success,
            None on failure.

    """
    try:
        userinfo_endpoint = "https://api.github.com/user"
        email_endpoint = "https://api.github.com/user/emails"

        # Setup retry strategy
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            backoff_factor=1,  # A backoff factor to apply between attempts
        )
        # Create an HTTP adapter with the retry strategy and mount it to session
        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Create a new session object
        session = requests.Session()
        session.mount("https://", adapter)

        # Make a request to fetch user info
        response = session.get(userinfo_endpoint, headers={"Authorization": f"token {access_token}"})

        # Check response for user info
        if response.status_code == 200:
            userdata = response.json()
            logger.info({"GitHub userdata": userdata})

            # Make a request to fetch user's email
            email_response = session.get(email_endpoint, headers={"Authorization": f"token {access_token}"})

            if email_response.status_code == 200:
                emails = email_response.json()
                # Assuming the first email is the primary one
                primary_email = emails[0]["email"] if emails else None
            else:
                logger.error(f"Error fetching GitHub user email, status_code={email_response.status_code}")
                primary_email = None

            return {
                "id": userdata["id"],
                "email": primary_email,
                "name": userdata.get("name"),
                "avatar": userdata.get("avatar_url"),
            }
        else:
            logger.error(f"Error fetching GitHub user info, status_code={response.status_code}")
            return None
    except Exception as e:
        logger.exception(f"FetchGitHubUserInfoError: {str(e)}")
        return None
