class ResourceAuthorizationError(Exception):  # -> Response 401
    """
    Exception raised when authorization for a specific resource fails.

    This error is thrown when an attempt to access or modify a resource
    is blocked due to lack of proper authorization or permissions.
    """


class UnverifiedEmailError(Exception):  # -> 403 Forbidden (unverifiedEmail)
    """
    Exception raised when an action requires a verified email, but the user's email is unverified.

    This error signifies that the requested operation is forbidden until the user's email address
        has been verified.
    """


class ResourceAccessError(Exception):  # -> 403 Forbidden
    """
    Exception raised when access to a specific resource is denied.

    This error is thrown when an operation on a resource is attempted
        by a user who does not have the required permissions.
    """


class ResourceNotFoundError(Exception):  # -> Response 404
    """
    Exception raised when a specific resource is not found.

    This error is used to signify the absence of a required resource,
    which could be a file, database entry, or any other type of resource
    that is expected to be present but is not available or does not exist.
    """


class UserAlreadyRegisteredError(Exception):  # -> 409 Conflict (accountExists)
    """
    Exception raised when an attempt is made to register a user that already exists.

    This error indicates a conflict because the user trying to be registered
        has an existing account or record in the system.
    """


class UserAlreadySubscribedError(Exception):  # -> 409 Conflict (subscriptionExists)
    """
    Exception raised when an attempt is made to subscribe a user that is already subscribed.

    This error indicates a conflict because the user trying to be subscribed
        already has an active subscription in the system.
    """
