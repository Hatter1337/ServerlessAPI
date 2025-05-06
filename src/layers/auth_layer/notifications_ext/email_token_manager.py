import hmac
import time
import json
import base64
import hashlib
import logging
from functools import cached_property


class EmailTokenManager:
    """
    A class to generate and verification email-tokens containing an email and an expiration timestamp.

    """

    def __init__(self, secret_key, logger=None):
        """
        Initializes the EmailTokenManager with a secret key.

        Args:
            secret_key (str): A secret key used for token generation and verification.

        """
        self.secret_key = secret_key.encode()
        self._logger = logger

    @cached_property
    def logger(self):
        if self._logger:
            return self._logger

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        return logger

    @staticmethod
    def encode_payload(payload):
        """
        Encodes the payload to a base64 string.

        Args:
            payload (dict): A dictionary containing the payload.

        Returns:
            str: A base64 encoded string.

        """
        json_payload = json.dumps(payload).encode()
        return base64.urlsafe_b64encode(json_payload).decode()

    @staticmethod
    def decode_payload(encoded_payload):
        """
        Decodes the base64 encoded payload back to a dictionary.

        Args:
            encoded_payload (str): A base64 encoded payload string.

        Returns:
            dict: A dictionary of the decoded payload or None if decoding fails.

        """
        try:
            json_payload = base64.urlsafe_b64decode(encoded_payload.encode())
            return json.loads(json_payload)
        except Exception as e:  # noqa
            return None

    def generate_signature(self, message):
        """
        Generates a HMAC signature for the message.

        Args:
            message (str): The message to sign.

        Returns:
            str: The generated signature as a base64 encoded string.

        """
        return base64.urlsafe_b64encode(hmac.new(self.secret_key, message.encode(), hashlib.sha256).digest()).decode()

    def generate_token(self, email, token_type, validity_period=86400):  # default = 24 hours
        """
        Generates a token with the given email and validity period.

        Args:
            email (str or EmailSrt): A user email to encode in the token.
            token_type (str): Token type: "log_in" / "sign_up".
            validity_period (int): The validity period of the token in seconds.

        Returns:
            str: A generated token.

        """
        payload = {"email": email, "type": token_type, "exp": int(time.time()) + validity_period}
        encoded_payload = self.encode_payload(payload)
        signature = self.generate_signature(encoded_payload)
        return f"{encoded_payload}.{signature}"

    def verify_token(self, token):
        """
        Verifies the given token and returns the payload with user email if the token is valid.

        Args:
            token (str): The token to verification.

        Returns:
            tuple: A tuple of
                a boolean indicating the verification result and
                the payload if verified.

        """
        try:
            if not token:
                return False, None

            encoded_payload, signature = token.rsplit(".", 1)
            expected_signature = self.generate_signature(encoded_payload)

            if not hmac.compare_digest(signature, expected_signature):
                return False, None

            payload = self.decode_payload(encoded_payload)

            if payload is None or not all(key in payload for key in ("exp", "email", "type")):
                return False, None

            if payload["exp"] < time.time():
                return False, None

            return True, payload
        except ValueError:
            return False, None
