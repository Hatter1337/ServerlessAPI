from abc import ABC, abstractmethod


class AbstractEncryptor(ABC):
    """
    An abstract class for encrypting and decrypting data.

    """

    @abstractmethod
    def encrypt(self, data: str) -> str:
        """
        Encrypts the provided data.

        Args:
            data (str): The plaintext data to be encrypted.

        Returns:
            str: The encrypted data.

        """

    @abstractmethod
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypts the provided data.

        Args:
            encrypted_data (str): The encrypted data to be decrypted.

        Returns:
            str: The decrypted data.

        """
