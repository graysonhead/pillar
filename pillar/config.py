import yaml
from pathlib import PosixPath

UNSET = object


class OptionNotValid(Exception):
    pass


class ConfigOption:

    def __init__(self,
                 attribute: str,
                 valid_types: list,
                 default_value=None,
                 description: str = None,
                 example: str = None):
        self.attribute = attribute
        self.valid_types = valid_types
        self.default_value = default_value
        self.description = description
        if example:
            self.example = example
        else:
            if default_value:
                self.example = default_value
        self.value = UNSET

    def _parse_poisx_path(self, path: str):
        return PosixPath(path).expanduser()

    def set(self, value=None) -> None:
        if not value:
            if PosixPath in self.valid_types:
                self.value = self._parse_poisx_path(self.default_value)
            else:
                self.value = self.default_value
        else:
            if PosixPath in self.valid_types:
                self.value = self._parse_poisx_path(value)
            elif type(value) in self.valid_types:
                self.value = value
            else:
                raise TypeError(f"Option {self.attribute} cannot accept value "
                                f"{value}. It must be one of the following "
                                f"types {self.valid_types}.")

    def get(self):
        if self.value == UNSET:
            self.set()
        return self.value


class Config:
    """
    Configuration options and yaml file loading and saving.

    When creating from a .yaml file, use the .load_from_yaml() class method,
    which will return an instance with values populated from the file path
    provided.
    """

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            self.set_value(key, value)

    @classmethod
    def load_from_yaml(cls, path: str):
        with open(path, 'r') as file:
            file_dict = yaml.load(file, Loader=yaml.FullLoader)
        if file_dict:
            return cls(**file_dict)
        else:
            return cls()

    def _return_option_instance(self, option_name: str) -> ConfigOption:
        try:
            return next(
                filter(lambda i: i.attribute == option_name, self.options)
            )
        except StopIteration:
            raise OptionNotValid(f"{option_name} is not a valid configuration "
                                 f"option.")

    def set_value(self, option_name: str, value):
        option = self._return_option_instance(option_name)
        option.set(value=value)

    def get_value(self, option_name: str):
        option = self._return_option_instance(option_name)
        return option.get()

    def get_dict(self) -> dict:
        return_dict = {}
        for option in self.options:
            return_dict.update({option.attribute: option.get()})
        return return_dict

    def generate_config(self, path: str) -> None:
        with open(path, 'w') as file:
            file.write(self.generate_yaml())

    def generate_yaml(self) -> str:
        default_option_dict = {}
        for option in self.options:
            option_value = option.get()
            if PosixPath in option.valid_types:
                option_value = str(option.get())
            default_option_dict.update(
                {option.attribute: option_value}
            )
        return yaml.dump(default_option_dict)


class PillardConfig(Config):

    options = [
        ConfigOption(
            'db_path',
            [PosixPath],
            default_value='~/.pillar/pillar.db',
            description="Path of SQLite database."
        ),
        ConfigOption(
            'ipfs_url',
            [str],
            default_value="http://127.0.0.1:8080",
            description="URL of IPFS API connection."
        ),
        ConfigOption(
            'config_directory',
            [PosixPath],
            default_value="~/.pillar",
            description="Path of Pillar configuration directory."
        ),
        ConfigOption(
            'ipfs_directory',
            [PosixPath],
            default_value="~/.pillar/ipfs",
            description="Filesystem path where ipfs content is downloaded."
        ),
        ConfigOption(
            'default_key_type',
            [str],
            default_value="RSA",
            description="GPG Key Type."
        ),
        ConfigOption(
            'default_key_length',
            [int],
            default_value=4096,
            description="Default length of generated keys."
        ),
        ConfigOption(
            'default_subkey_type',
            [str],
            default_value="RSA",
            description="Default type of generated subkeys."
        ),
        ConfigOption(
            'default_subkey_length',
            [int],
            default_value=4096,
            description="Default length of generated subkeys."
        ),
        ConfigOption(
            'default_subkey_duration',
            [int],
            default_value=0,
            description="Default valid duration of subkeys, 0 for infinite."
        ),
        ConfigOption(
            'channel_rotation_period',
            [int],
            default_value=0,
            description="Interval for new channel generation."
        ),
        ConfigOption(
            'channels_per_peer',
            [int],
            default_value=1,
            description="Length of channel list generated by channel"
                        " generator."
        ),
        ConfigOption(
            'ipfs_workers',
            [int],
            default_value=2,
            description="Number of IPFS worker threads to run."
        ),
        ConfigOption(
            'use_unix_socket',
            [bool],
            default_value=True,
            description="Listens for pillarctl commands on a unix socket."
        ),
        ConfigOption(
            'local_unix_socket_path',
            [str],
            default_value='/tmp/pillar_socket',
            description="Path of the local socket used for pillarctl commands."
        ),
        ConfigOption(
            'ipfs_hostname',
            [str],
            default_value='localhost',
            description="Hostname or IP address of IPFS API server."
        ),
        ConfigOption(
            'ipfs_port',
            [int],
            default_value=5001,
            description="Port of IPFS API server."
        )
    ]


def get_ipfs_config_options(config: PillardConfig):
    return_dict = {}
    return_dict.update({'host': config.get_value('ipfs_hostname')})
    return_dict.update({'port': config.get_value('ipfs_port')})
    return return_dict
