import json
import logging
from datetime import datetime, timedelta, UTC
from functools import cached_property
from jose import jwt, JWTError


class JWTAuthenticator:
    """
    A class to manage the creation, decoding, and refreshing of JWT tokens.

    Attributes:
        secret_key (bytes): The secret key used for token encryption and decryption.
        algorithm (str): The algorithm used for JWT encoding and decoding.

    """

    def __init__(self, secret_key, algorithm="HS256", logger=None):
        """
        Initializes the TokenManager with a secret key and algorithm.

        Args:
            secret_key (str): A secret key used for JWT encoding and decoding.
            algorithm (str): The JWT encoding/decoding algorithm to use.

        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self._logger = logger

    @cached_property
    def logger(self):
        if self._logger:
            return self._logger

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        return logger

    def create_token(self, sub_claims: dict, expires: datetime):
        """
        Creates a JWT token with the given claims and expiration time.

        Args:
            sub_claims (dict): A dictionary containing the claims to be included in the token.
            expires (datetime): The expiration time of the token.

        Returns:
            str: The encoded JWT token.

        """
        return jwt.encode(
            {
                "sub": json.dumps(sub_claims),
                "exp": expires,
            },
            self.secret_key,
            algorithm=self.algorithm,
        )

    def create_tokens(self, user_data: dict):
        """
        Creates access and refresh JWT tokens for the given user data.

        Args:
            user_data (dict): User data to encode in the JWT access token.

        Returns:
            dict: A dictionary containing 'access_token' and 'refresh_token'.

        """
        access_token_expires = datetime.now(UTC) + timedelta(minutes=60)
        refresh_token_expires = datetime.now(UTC) + timedelta(days=30)

        # Define claims for JWT access token
        access_sub_claims = {
            key: user_data[key]
            for key in ("id", "name", "email", "avatar", "api_key", "workspaces")
            if key in user_data
        }

        # Define claims for JWT refresh token, only include identifier value
        refresh_sub_claims = {
            "id": user_data["id"],
        }

        return {
            "access_token": self.create_token(access_sub_claims, access_token_expires),
            "refresh_token": self.create_token(refresh_sub_claims, refresh_token_expires),
            "access_token_expires_in": access_token_expires,
            "refresh_token_expires_in": refresh_token_expires,
        }

    def decode_token(self, token: str):
        """
        Decodes a JWT token and checks for expiration.

        Args:
            token (str): The JWT token to decode.

        Returns:
            dict: The decoded data contained in the token if successful, None otherwise.

        """
        try:
            decoded_data = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return json.loads(decoded_data.get("sub", "{}"))
        except JWTError as e:
            self.logger.error(f"Token decode error: {e}")
            return None

    def refresh_access_token(self, refresh_token, get_user_fn):
        """
        Generates a new access token using the provided refresh token.

        Args:
            refresh_token (str): The refresh token used to generate a new access token.
            get_user_fn (callable): A function that takes an identifier and returns user data.

        Returns:
            str: A new access token, or None if the refresh token is invalid.

        """
        decoded_data = self.decode_token(refresh_token)

        if decoded_data and decoded_data.get("id"):
            # Call the provided function to get user data
            #   based on the ID from the decoded refresh_token
            user_data = get_user_fn(decoded_data["id"])

            if user_data:
                # Generate a new access token using the obtained user data
                return self.create_tokens(user_data)["access_token"]
