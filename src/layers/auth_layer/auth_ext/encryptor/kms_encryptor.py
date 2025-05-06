import boto3
from base64 import b64encode, b64decode

from auth_ext.encryptor.abstract import AbstractEncryptor


class KMSEncryptor(AbstractEncryptor):
    """
    Encryptor class that uses AWS KMS for encryption and decryption.

    """

    def __init__(self, kms_key_arn, region="eu-west-2"):
        """
        Initializes the KMSEncryptor with the ARN of the AWS KMS key.

        Args:
            kms_key_arn (str): The ARN of the AWS KMS key to use for encryption and decryption.
            region (str): AWS Region name.

        """
        self.kms_client = boto3.client("kms", region_name=region)
        self.kms_key_arn = kms_key_arn

    def encrypt(self, data: str) -> str:
        """
        Encrypts the provided data using AWS KMS.

        Args:
            data (str): The plaintext data to be encrypted.

        Returns:
            str: The encrypted data, base64-encoded.

        """
        response = self.kms_client.encrypt(KeyId=self.kms_key_arn, Plaintext=data.encode("utf-8"))
        encrypted_data = b64encode(response["CiphertextBlob"]).decode("utf-8")
        return encrypted_data

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypts the provided data using AWS KMS.

        Args:
            encrypted_data (str): The encrypted data to be decrypted, base64-encoded.

        Returns:
            str: The decrypted data.

        """
        decrypted_response = self.kms_client.decrypt(CiphertextBlob=b64decode(encrypted_data))
        decrypted_data = decrypted_response["Plaintext"].decode("utf-8")
        return decrypted_data
