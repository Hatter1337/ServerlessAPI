from abc import ABCMeta, abstractmethod


class AbstractClassProperty:
    """Special class to create abstract property."""

    def __init__(self, expect=None):
        self.expect = expect

        self.name = None
        self.owner = None

    def __set_name__(self, owner, name):
        self.name = name
        self.owner = owner

    def __set__(self, instance, value):
        raise NotImplementedError(
            f"Redefine attribute '{self.name}' in class '{self.owner.__name__}'" f" expect {self.expect}"
            if self.expect
            else ""
        )

    def __get__(self, instance, owner):
        raise NotImplementedError(
            f"Redefine attribute '{self.name}' in class '{self.owner.__name__}'" f" expect {self.expect}"
            if self.expect
            else ""
        )


class AbstractLoader(metaclass=ABCMeta):
    """Abstract class for all config_ loaders."""

    @classmethod
    @abstractmethod
    def load(cls, *args, **kwargs):
        """
        Load config_ data from resource.

        Returns:
            dict: config_ data

        """


class AbstractValidator(metaclass=ABCMeta):
    """Abstract class for config_ validators."""

    @classmethod
    @abstractmethod
    def check(cls, config_data):
        """
        Validate config_ data.

        Args:
            config_data (dict): config_ data to validate

        Returns:
            dict: validate data

        """


class DummyValidator(AbstractValidator):
    """Validator to do not validate anything."""

    @classmethod
    def check(cls, config_data):
        """
        Do not validate config_ data.

        Args:
            config_data (dict): config_ data to validate

        Returns:
            dict: config_ data

        """
        return config_data
