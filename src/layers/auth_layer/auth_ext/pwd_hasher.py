import base64
import hashlib
import hmac
import secrets


class PasswordHasher:
    """
    Password hasher class using PBKDF2 (SHA256) for hashing and verifying passwords.

    Attributes:
        iterations (int): Number of iterations for PBKDF2. Higher = more secure but slower.
    """

    def __init__(self, iterations=100_000):
        """
        Initializes the Password Hasher instance with the specified number of iterations.
        """
        self.iterations = iterations

    @staticmethod
    def generate_salt(length=16):
        """
        Generates a secure random salt.

        Returns:
            str: Base64 encoded salt.
        """
        salt = secrets.token_bytes(length)
        return base64.urlsafe_b64encode(salt).decode("utf-8")

    def hash_password(self, password: str, salt: str) -> str:
        """
        Hashes a password using PBKDF2 with SHA256.

        Args:
            password (str): The password to hash.
            salt (str): Base64 encoded salt.

        Returns:
            str: Base64 encoded hash.
        """
        salt_bytes = base64.urlsafe_b64decode(salt.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, self.iterations)
        return base64.urlsafe_b64encode(dk).decode("utf-8")

    def verify_password(self, password: str, salt: str, hashed_password: str) -> bool:
        """
        Verifies a password against the given salt and hash.

        Args:
            password (str): The password to verify.
            salt (str): Base64 encoded salt used when hashing the original password.
            hashed_password (str): Base64 encoded stored hash.

        Returns:
            bool: True if the password matches, False otherwise.
        """
        new_hash = self.hash_password(password, salt)
        return hmac.compare_digest(new_hash, hashed_password)
