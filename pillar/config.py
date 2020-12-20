import yaml
import os

class Config(object):
    path = os.path.expanduser("~")+'/.config/computecommunity/config'
    ipfs_url = "http://127.0.0.1:8080"
    gpghome = os.path.expanduser("~")+'/.config/computecommunity/'
    configdir = os.path.expanduser("~")+'/.config/computecommunity/'
    pubkey_path = os.path.expanduser("~")+'/.config/computecommunity/pubkey'
    default_key_type = "RSA"
    default_key_length = 4096
    my_user_cid = None

    def __init__(self, path = None):
        option_attrib_dict = {
                   "ipfs_url": self.__class__.ipfs_url,
                   "gpghome": self.__class__.gpghome,
                   "default_key_length": self.__class__.default_key_length,
                   "default_key_type": self.__class__.default_key_type,
                   "my_user_cid": self.__class__.my_user_cid,
        }
        
        if path is not None:
            self.__class__.path = path

        os.makedirs(self.configdir, exist_ok=True)

        with open(self.path, 'w+') as f:
            self.file_content = yaml.load(f)
            if self.file_content is not None:
                for option_name, class_attribute in option_attrib_dict.items():
                    self.attempt_load_option_from_file(option_name, class_attribute)

    def attempt_load_option_from_file(self, option_name, class_attribute):
        try:
            class_atribute = self.file_content[option_name]
        except KeyError:
            pass        
        
