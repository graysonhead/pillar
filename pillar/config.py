import yaml
import os

class Config:
    """
    Configuration options and yaml file loading. To load a custom instance of 
    """
    path = os.path.expanduser("~")+'/.config/computecommunity/config'
    ipfs_url = "http://127.0.0.1:8080"
    gpghome = os.path.expanduser("~")+'/.config/computecommunity/'
    configdir = os.path.expanduser("~")+'/.config/computecommunity/'
    pubkey_path = os.path.expanduser("~")+'/.config/computecommunity/pubkey'
    default_key_type = "RSA"
    default_key_length = 4096
    my_user_cid = None
    option_attribs = ["ipfs_url",
                          "gpghome",
                          "default_key_length",
                          "default_key_type",
                          "my_user_cid"]

    def __init__(self, path = None):
        self.load_file(path)

    def load_file(self, path = None):
        """Load the config file."""
        if path is not None:
            self.__class__.path = path
        os.makedirs(self.configdir, exist_ok=True)

        with open(self.path, 'w+') as file:
            self.file_content = yaml.load(file)
            if self.file_content is not None:
                for option_name in self.option_attribs:
                    try:
                        setattr(self, option_name, self.file_content[option_name])
                    except KeyError:
                        pass
    
