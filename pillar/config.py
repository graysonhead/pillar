import yaml

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

    def set(self, value=None) -> None:
        if not value:
            self.value = self.default_value
        else:
            if type(value) in self.valid_types:
                self.value = value
            else:
                raise TypeError(f"Option {self.attribute} cannot accept value "
                                f"{value}. It must be one of the following "
                                f"types {self.valid_types}.")

    def get(self):
        if self.value == UNSET:
            return self.default_value
        else:
            return self.value


class Config:
    """
    Configuration options and yaml file loading and saving.

    When creating from a .yaml file, use the .load_from_yaml() class method,
    which will return an instance with values populated from the file path
    provided.
    """
    options = [
        ConfigOption(
            'db_path',
            [str],
            default_value='/var/lib/pillar/pillar.db',
            description="Filesystem path where the sqlite database is located"
        ),
        ConfigOption(
            'ipfs_url',
            [str],
            default_value="http://127.0.0.1:8080",
            description="URL of IPFS API connection"
        ),
        ConfigOption(
            'config_directory',
            [str],
            default_value="/etc/pillar",
            description="Path of Pillar configuration directory"
        ),
        ConfigOption(
            'ipfs_directory',
            [str],
            default_value="/var/lib/pillar/ipfs",
            description="Filesystem path where ipfs content is downloaded."
        ),
        ConfigOption(
            'public_key_path',
            [str],
            default_value="/etc/pillar/key.pub"
        ),
        ConfigOption(
            'default_key_type',
            [str],
            default_value="RSA",
            description="GPG Key Type"
        ),
        ConfigOption(
            'default_key_length',
            [int],
            default_value=4096,
            description="Default length of generated keys"
        ),
        ConfigOption(
            'default_subkey_type',
            [str],
            default_value="RSA",
            description="Default type of generated subkeys"
        ),
        ConfigOption(
            'default_subkey_length',
            [int],
            default_value=4096,
            description="Default length of generated subkeys"
        ),
        ConfigOption(
            'default_subkey_duration',
            [int],
            default_value=0,
            description="Default valid duration of subkeys, 0 for infinite"
        )
    ]

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            self.set_value(key, value)

    @classmethod
    def load_from_yaml(cls, path: str):
        with open(path, 'r') as file:
            file_dict = yaml.load(file, Loader=yaml.FullLoader)
        return Config(**file_dict)

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
        return option.value

    def get_dict(self) -> dict:
        return_dict = {}
        for option in self.options:
            return_dict.update({option.attribute: option.get()})
        return return_dict

    def generate_default(self, path: str) -> None:
        default_option_dict = {}
        for option in self.options:
            default_option_dict.update(
                {option.attribute: option.default_value}
            )
        with open(path, 'w') as file:
            file.write(yaml.dump(default_option_dict))
