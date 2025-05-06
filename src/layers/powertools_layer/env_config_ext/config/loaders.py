import os

from env_config_ext.config.abstracts import AbstractLoader


class ObjectLoader(AbstractLoader):
    """
    Loader to load config data from Python object.
    Extracts only uppercase attributes from object (similar to environment variables).

    """

    @classmethod
    def load(cls, obj):
        """
        Load data from Python object.

        Args:
            obj (any): Python obj

        Returns:
            dict: config data

        """
        return dict((param_name, getattr(obj, param_name)) for param_name in filter(str.isupper, dir(obj)))


class ENVLoader(AbstractLoader):
    """Loader to load config data from environment."""

    @staticmethod
    def filter_config(config, prefix):
        """
        Filter config by specified prefix.

        Args:
            config (dict): config data
            prefix (str): prefix by which the search for the desired variable is performed

        Returns:
            dict: config data

        """
        return {key: value for key, value in config.items() if key.startswith(prefix)}

    @classmethod
    def load(cls, prefix=None):
        """
        Load config data from environment.

        Args:
            prefix (str): indicated when need a part of the config
                with variables that start with the specified prefix

        Returns:
            dict: config data

        """
        env_config = dict(os.environ)
        return env_config if prefix is None else cls.filter_config(env_config, prefix)
