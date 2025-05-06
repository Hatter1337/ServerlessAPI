import time
import boto3
import logging
from functools import cached_property
from dataclasses import dataclass, asdict

from botocore.exceptions import ClientError

from env_config_ext import env_config

DEFAULT_TABLE_NAME = f"sla-email-rate-limiter-{env_config['ENVIRONMENT']}"


@dataclass
class RateLimit:
    """Class for keeping track of email rate limits."""

    rule: str
    retry_after: int

    def to_dict(self):
        """Returns the RateLimit data as a dictionary."""
        return asdict(self)


class EmailRateLimiter:
    """
    A class for limiting email sending rate using DynamoDB.

    This class uses a DynamoDB table to track and limit the rate of email sending
        according to specified rules.

    """

    def __init__(self, table_name=DEFAULT_TABLE_NAME, logger=None):
        """
        Initializes the EmailRateLimiter with the DynamoDB table name.

        Args:
            table_name (str): table that stores information about the recently sent emails by email.
            logger (logging.Logger, optional): Custom logger for logging messages.

        """
        self.table_name = table_name
        self._logger = logger

    @cached_property
    def table(self):
        resource = boto3.resource("dynamodb")
        return resource.Table(self.table_name)

    @cached_property
    def logger(self):
        if self._logger:
            return self._logger

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        return logger

    @property
    def current_time(self):
        """Returns the current Unix timestamp in seconds."""
        return int(time.time())

    @staticmethod
    def check_rate_limits(counter, time_since_last_sent):
        """
        Evaluates if sending an email exceeds predefined rate limits.

        Args:
            counter (int): Number of emails sent in the current period.
            time_since_last_sent (int): Seconds since the last email was sent.

        Returns:
            (bool, int | None): False and value of the limit that was exceeded in seconds,
                otherwise True and None.

        """
        if counter <= 5 and time_since_last_sent < 60:
            rule = "One email per minute"
            return False, RateLimit(rule=rule, retry_after=60 - time_since_last_sent)
        elif counter > 5 and time_since_last_sent < 180:
            rule = "One email per 3 minutes, after more than 5 emails sent in the last hour"
            return False, RateLimit(rule=rule, retry_after=180 - time_since_last_sent)
        elif counter > 10 and time_since_last_sent < 300:
            rule = "One email per 5 minutes, after more than 10 emails sent in the last hour"
            return False, RateLimit(rule=rule, retry_after=300 - time_since_last_sent)

        return True, None

    def can_send_email(self, email):
        """
        Determines if an email can be sent to a user based on the rate limiting rules.

        Args:
            email (str): The user's email.

        Returns:
            tuple[bool, int]: A tuple where the first element is a boolean indicating
                if the email can be sent, and the second element is a value of the limit
                that was exceeded in seconds if the email cannot be sent, otherwise None.

        """
        try:
            response = self.table.get_item(Key={"email": email})
            item = response.get("Item")

            if not item:
                return True, None  # User record does not exist, email can be sent.

            last_sent_at = int(item["last_sent_at"])
            counter = int(item["counter"])
            time_since_last_sent = self.current_time - last_sent_at

            # Check the rate limiting rules
            return self.check_rate_limits(counter, time_since_last_sent)
        except ClientError as error:
            self.logger.exception(f"An error occurred: {str(error)}")
            raise error

    def update_send_email_limiter(self, email):
        """
        Updates or creates a limiter for a user when an email is sent.

        Args:
            email (str): The user's email.

        Raises:
            Exception: If there is an error, update the DynamoDB table.

        """
        current_time = self.current_time
        ttl = current_time + 3600  # 1 hour from now

        try:
            self.table.update_item(
                Key={"email": email},
                UpdateExpression="SET last_sent_at = :last_sent_at, #cntr = if_not_exists(#cntr, :init) + :inc, #ttl = :ttl",  # noqa
                ExpressionAttributeNames={"#cntr": "counter", "#ttl": "ttl"},
                ExpressionAttributeValues={
                    ":last_sent_at": current_time,
                    ":init": 0,
                    ":inc": 1,
                    ":ttl": ttl,
                },
            )
        except ClientError as error:
            self.logger.exception(f"Failed to update the email sending limiter: {str(error)}")
            raise error
