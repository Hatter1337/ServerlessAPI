import boto3
import logging
from functools import cached_property
from botocore.exceptions import ClientError

from notifications_ext.email_rate_limiter import EmailRateLimiter


class EmailNotifierLimitExceededError(Exception):
    """Base exception for email notifier rate limits."""

    def __init__(self, rule, retry_after):
        """
        Initializes the EmailNotifierLimitExceededError.

        Args:
            rule (str): rate limit rule details.
            retry_after (int): value showing after how many seconds resending will be available.

        """
        self.rule = rule
        self.retry_after = retry_after


class EmailNotifierDeliveryError(Exception):
    """Base exception for email notifier failed delivery."""


class EmailNotifier:
    """
    A class to manage user email interactions,
        including sending email verification links and direct login links using AWS SES.

    """

    def __init__(
        self,
        sender_email="noreply.qr.flow@gmail.com",
        rate_limiter=EmailRateLimiter,
        aws_region="eu-west-2",
        logger=None,
    ):
        """
        Initializes the UserEmailService with the sender's email and AWS region.

        Args:
            sender_email (str): The email address verified with AWS SES to send emails from.
            aws_region (str): The AWS region where SES is configured and verified.
            logger (logging.Logger, optional): Custom logger for logging messages.

        """
        self.sender_email = sender_email
        self.client = boto3.client("ses", region_name=aws_region)

        self._logger = logger
        self.rate_limiter = rate_limiter(logger=self.logger)

    @cached_property
    def logger(self):
        if self._logger:
            return self._logger

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        return logger

    def send_verification_email(self, recipient_email, verification_link):
        """
        Sends a verification email to the specified recipient.

        Args:
            recipient_email (str or EmailStr): The email address of the recipient.
            verification_link (str): The verification link to be included in the email.

        Returns:
            bool: True if the email was successfully sent; False otherwise.

        """
        subject = "QRFlow - verification your email"
        body_html = f"""
            <html>
            <head></head>
            <body>
              <h1>Welcome to QRFlow!</h1>
              <p>We're excited to have you on board. To get started, 
              please verification your email address by clicking the link below:</p>
              <p><a href="{verification_link}">Verify Email</a></p>
              <p>If you did not sign up for this account, you can ignore this email.</p>
            </body>
            </html>
        """
        body_text = (
            f"Welcome to QRFlow!\n\nWe're excited to have you on board. "
            f"To get started, please verification your email address by clicking the link "
            f"below:\n{verification_link}\n\nIf you did not sign up for this account, "
            f"you can ignore this email."
        )

        return self._send_email_with_limiter(recipient_email, subject, body_html, body_text)

    def send_password_confirmation_email(self, recipient_email, verification_link):
        """
        Sends a password confirmation email to the specified recipient.
        This email is sent after the user has successfully created a password.

        Args:
            recipient_email (str): The email address of the recipient.
            verification_link (str): The verification link for confirming the newly set password.

        Returns:
            bool: True if the email was successfully sent; False otherwise.

        """
        subject = "QRFlow - confirm your password"
        body_html = f"""
            <html>
            <head></head>
            <body>
              <h1>Your password is almost ready</h1>
              <p>Thank you for setting up your password. Before you can use it to log in, 
              we just need to make sure it was really you. 
              Please confirm your password by clicking the link below:</p>
              <p><a href="{verification_link}">Confirm Password</a></p>
              <p>This is an important step in securing your QRFlow account.</p>
              <p>If you did not request a password, you can ignore this email.</p>
            </body>
            </html>
        """
        body_text = (
            "Your password is almost ready\n\n"
            "Thank you for setting up your password. Before you can use it to log in, "
            "we just need to make sure it was really you. "
            "Please confirm your password by clicking the link below:\n"
            f"{verification_link}\n\nThis is an important step in securing your QRFlow account.\n\n"
            "If you did not request a password, you can ignore this email."
        )

        return self._send_email_with_limiter(recipient_email, subject, body_html, body_text)

    def send_login_email(self, recipient_email, login_link):
        """
        Sends an email to the specified recipient with a direct login link.

        Args:
            recipient_email (str): The email address of the recipient.
            login_link (str): The direct login link to be included in the email.

        Returns:
            bool: True if the email was successfully sent; False otherwise.

        """
        subject = "QRFlow - log in to your account"
        body_html = f"""
            <html>
            <head></head>
            <body>
              <h1>Log In Made Easy</h1>
              <p>You can directly log in to your QRFlow account using the link below:</p>
              <p><a href="{login_link}">Log In</a></p>
              <p>This link is valid for 24 hours for your security.</p>
              <p>If you did not request a direct login, please secure your account.</p>
            </body>
            </html>
        """
        body_text = (
            f"Log In Made Easy\n\nYou can directly log in to your account "
            f"using the link below:\n{login_link}\n\n"
            f"This link is valid for 24 hours for your security.\n\n"
            f"If you did not request a direct login, please secure your account."
        )

        return self._send_email_with_limiter(recipient_email, subject, body_html, body_text)

    def send_forgot_password_email(self, recipient_email, reset_link):
        """
        Sends a forgot password email to the specified recipient.

        Args:
            recipient_email (str or EmailStr): The email address of the recipient.
            reset_link (str): The password reset link to be included in the email.

        Returns:
            bool: True if the email was successfully sent; False otherwise.

        """
        subject = "QRFlow - Password Reset Request"
        body_html = f"""
            <html>
            <head></head>
            <body>
              <h1>Password Reset Request</h1>
              <p>We received a request to reset your password. 
              Please use the link below to set a new password:</p>
              <p><a href="{reset_link}">Reset Password</a></p>
              <p>If you did not request this, 
              please ignore this email or contact support if you have concerns.</p>
            </body>
            </html>
        """
        body_text = (
            f"Password Reset Request\n\n"
            f"We received a request to reset your password. "
            f"Please use the link below to set a new password:\n{reset_link}\n\n"
            f"If you did not request this, "
            f"please ignore this email or contact support if you have concerns."
        )

        return self._send_email_with_limiter(recipient_email, subject, body_html, body_text)

    def _send_email(self, recipient_email, subject, body_html, body_text):
        """
        Sends an email with the provided subject, HTML body,
            and text body to the specified recipient.

        This is an internal method used to abstract the common functionality of sending an email.

        Args:
            recipient_email (str): The recipient's email address.
            subject (str): The subject of the email.
            body_html (str): The HTML body of the email.
            body_text (str): The text body of the email.

        Returns:
            bool: True if the email was successfully sent; False otherwise.

        """
        try:
            response = self.client.send_email(
                Destination={
                    "ToAddresses": [
                        recipient_email,
                    ],
                },
                Message={
                    "Body": {
                        "Html": {
                            "Charset": "UTF-8",
                            "Data": body_html,
                        },
                        "Text": {
                            "Charset": "UTF-8",
                            "Data": body_text,
                        },
                    },
                    "Subject": {
                        "Charset": "UTF-8",
                        "Data": subject,
                    },
                },
                Source=self.sender_email,
            )
        except ClientError as e:
            self.logger.error(f"Failed to send email: {e.response['Error']['Message']}")
            return False
        else:
            self.logger.info(f"Email sent! Message ID: {response['MessageId']}")
            return True

    def _send_email_with_limiter(self, recipient_email, subject, body_html, body_text):
        """
        Attempts to send an email while respecting rate limiting constraints.
        This method checks if the email can be sent to the specified recipient
            based on the current rate limits.
        If the rate limit has not been exceeded, it proceeds to send the email.
        Otherwise, it returns an error indicating the rate limit issue.

        Args:
            recipient_email (str): The recipient's email address.
            subject (str): The subject of the email.
            body_html (str): The HTML body of the email.
            body_text (str): The text body of the email.

        Returns:
            tuple[bool, Optional[str]]: A tuple containing a boolean that indicates if the email
                was successfully sent or not, and a string that represents
                the type of error if the email was not sent.

        """
        can_send_email, rate_limit = self.rate_limiter.can_send_email(email=recipient_email)

        if rate_limit:
            raise EmailNotifierLimitExceededError(**rate_limit.to_dict())

        was_sending_successful = self._send_email(recipient_email, subject, body_html, body_text)

        if not was_sending_successful:
            raise EmailNotifierDeliveryError

        self.rate_limiter.update_send_email_limiter(email=recipient_email)
