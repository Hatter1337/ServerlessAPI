from env_config_ext.config.abstracts import DummyValidator
from env_config_ext.config.loaders import ObjectLoader, ENVLoader


class ConfigException(BaseException):
    """Main exception for all config exceptions."""


class UnknownParameter(ConfigException):
    """Can't find expect parameter error."""


class ConfigFileNotFoundException(ConfigException):
    """Can't find file use path."""


class Config(dict):
    """Config class."""

    def __init__(self, *args, defaults=None):
        defaults = args[1] if args else (defaults or {})
        super(Config, self).__init__(defaults or {})

    def __getattr__(self, item):
        if item in ("_pytestfixturefunction", "__bases__", "__test__"):  # pytest
            return
        elif item in self:
            return self[item]
        raise UnknownParameter("Can't find config parameter: {}".format(item))

    def __setattr__(self, key, value):
        if key not in dir(self):
            self[key] = value
        else:
            self.__dict__[key] = value

    def __getitem__(self, item):
        if item in self:
            return super(Config, self).__getitem__(item)
        raise UnknownParameter("Can't find config parameter: {}".format(item))

    def __getstate__(self):
        return tuple(self.items())

    def __setstate__(self, state):
        self.update(dict(state))

    def __repr__(self):
        return "<Config: {}>".format(id(self))

    def __str__(self):
        text = "Config: {}\n\tparams:\n{}"
        params = "\n".join("\t\t{}: {}".format(p_name, p_val) for p_name, p_val in self.items())

        return text.format(id(self), params)

    @classmethod
    def operated_update(cls, update_from, update_to, deep_update=True):
        """
        Deep update.

        Args:
            update_from (dict): updated object
            update_to (dict): updating object
            deep_update (bool): flag to use deep update logic

        Returns:
            dict: update result

        """
        for param, param_val in update_from.items():
            if param in update_to:
                if deep_update and isinstance(param_val, dict):
                    update_to[param] = cls.operated_update(
                        update_to=update_to[param],
                        update_from=update_from[param],
                        deep_update=deep_update,
                    )
                else:
                    update_to[param] = param_val

            else:
                update_to[param] = param_val

        return update_to

    def reload_config(self, new_config):
        """
        Reload config use data from new config.

        Args:
            new_config: new config

        Returns:
            Config: new config

        """
        self.clear()
        self.update(new_config)

        return self

    def from_env(self, prefix=None, validator=DummyValidator, deep_update=False):
        """
        Update config data from environment.

        Args:
            prefix (str): indicated when need a part of the config
                with variables that start with the specified prefix
            validator (AbstractValidator): validator to validate config data
            deep_update (bool): flag to use deep update logic

        Returns:
            Config: updated config

        """
        return self.operated_update(
            update_to=self,
            update_from=validator.check(ENVLoader.load(prefix=prefix)),
            deep_update=deep_update,
        )

    def from_obj(self, obj, validator=DummyValidator, deep_update=False):
        """
        Update config data from Python object.

        Args:
            obj (any): Python object
            validator (AbstractValidator): validator to validate config data
            deep_update (bool): flag to use deep update logic

        Returns:
            Config: updated config

        """
        return self.operated_update(
            update_to=self,
            update_from=validator.check(ObjectLoader.load(obj=obj)),
            deep_update=deep_update,
        )
