from env_config_ext import constants
from env_config_ext.config.config import Config

config = Config().from_obj(constants)
config.from_env(deep_update=True)

env_config = dict(config)
