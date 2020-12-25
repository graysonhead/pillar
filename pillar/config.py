import yaml
import os


class Config:
    """
    Configuration options and yaml file loading and saving.
    """
    path = os.path.expanduser("~")+'/.config/pillar/config.yaml'
    ipfs_url = "http://127.0.0.1:8080"
    gpghome = os.path.expanduser("~")+'/.config/pillar/'
    configdir = os.path.expanduser("~")+'/.config/pillar/'
    ipfsdir = os.path.expanduser("~")+'/.config/pillar/ipfs/'
    pubkey_path = os.path.expanduser("~")+'/.config/pillar/key.pub'
    default_key_type = "RSA"
    default_key_length = 4096
    user_cid = None
    option_attribs = ["ipfs_url",
                      "gpghome",
                      "configdir",
                      "ipfsdir",
                      "pubkey_path",
                      "default_key_length",
                      "default_key_type",
                      "user_cid"]

    def __init__(self, path=None):
        self.load_file(path=path)

    def load_file(self, path=None):
        """Load the config file."""
        if path is not None:
            self.path = path
        if not os.path.isfile(self.path):
            with open(self.path, 'r+') as config_file:
                pass

        os.makedirs(self.configdir, exist_ok=True)

        with open(self.path, 'r') as config_file:
            self.file_content = yaml.load(config_file, Loader=yaml.FullLoader)
            if self.file_content is not None:
                for option_name in self.option_attribs:
                    try:
                        self.__setattr__(option_name,
                                         self.file_content[option_name])
                    except KeyError:
                        pass

    def save(self, path=None):
        if path is None:
            path = self.path
        with open(path, 'w+') as f:
            f.write(yaml.dump(self.get_attrib_dict()))

    def get_attrib_dict(self):
        """convert configuration options to a dict for saving et al."""
        return {attrib: self.__dict__[attrib]
                for attrib in self.option_attribs}
