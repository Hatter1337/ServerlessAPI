from typing import ClassVar

from pydantic import EmailStr, SecretStr, field_validator


def unify_email(email: str) -> str:
    """
    Unify an email address by removing substrings after '+' in the local part.
    This approach is more general and doesn't focus on specific domain rules.

    Args:
        email (str): The email address to be unified.

    Returns:
        str: The unified email address, or an empty string if the email is invalid.

    """
    try:
        local, domain = email.split("@")
        # Ignore parts after '+' in the local part
        local = local.split("+")[0]
        # Simple domain validation (contains at least one dot and not starting/ending with a dot)
        if not domain or domain.startswith(".") or domain.endswith(".") or "." not in domain:
            return ""  # Invalid domain
        return f"{local}@{domain}"
    except ValueError:
        # In case the email doesn't have exactly one '@'
        return ""  # Invalid email


class EmailValidator:

    @field_validator("email")  # noqa
    @classmethod
    def unify_email_address(cls, email: EmailStr) -> str:
        return unify_email(str(email))


class PasswordValidator:
    _password_min_length: ClassVar[int] = 8

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: SecretStr):
        value = password.get_secret_value()
        password_requirements_error_msg = (
            f"Password must contain numbers, lowercase and "
            f"uppercase letters, and be at least {cls._password_min_length} characters long"
        )

        if len(value) < cls._password_min_length:
            raise ValueError(password_requirements_error_msg)

        if not any(char.isdigit() for char in value):
            raise ValueError(password_requirements_error_msg)

        if not any(char.isupper() for char in value):
            raise ValueError(password_requirements_error_msg)

        if not any(char.islower() for char in value):
            raise ValueError(password_requirements_error_msg)

        return password
