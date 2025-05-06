import base64
import secrets
from cryptography.fernet import Fernet

from auth_ext.encryptor.abstract import AbstractEncryptor


class CustomEncryptor(AbstractEncryptor):
    """
    Encryptor class for encrypting and decrypting strings using symmetric encryption (Fernet).

    Attributes:
        secret_key (bytes): A securely generated secret key for encryption and decryption.
        cipher_suite (Fernet): A Fernet instance initialized with the secret_key.

    """

    def __init__(self, secret_key=None):
        """
        Initializes the Encryptor instance
            by generating a secret key and preparing the encryption suite.

        """
        self.secret_key = secret_key or self.generate_fernet_key()
        self.cipher_suite = Fernet(self.secret_key.encode("utf-8"))

    @staticmethod
    def generate_fernet_key():
        """
        Generates a Fernet key.

        Returns:
            str: The generated secret key.

        """
        key = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(key).decode("utf-8")

    def encrypt(self, data):
        """
        Encrypts a string using Fernet symmetric encryption.

        Args:
            data (str): The string data to encrypt.

        Returns:
            str: The encrypted data, as a base64-encoded string.

        """
        # Ensure the data is in bytes
        data_bytes = data.encode("utf-8")

        encrypted_data = self.cipher_suite.encrypt(data_bytes)
        # Convert to string for consistency in return type
        return encrypted_data.decode("utf-8")

    def decrypt(self, encrypted_data):
        """
        Decrypts a previously encrypted string.

        Args:
            encrypted_data (str): The encrypted data, as a base64-encoded string.

        Returns:
            str: The decrypted data.

        """
        # Ensure encrypted_data is in bytes
        encrypted_data_bytes = encrypted_data.encode("utf-8")

        decrypted_data_bytes = self.cipher_suite.decrypt(encrypted_data_bytes)
        return decrypted_data_bytes.decode("utf-8")
