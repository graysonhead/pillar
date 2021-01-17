from pprint import pprint
from pillar.config import Config
from pillar.keymanager import KeyManager, EncryptionHelper, PillarKeyType
from pillar.identity import User, Node
from pprint import pprint
import os
import shutil
import logging
import time


def remove_directories_idempotently():
    dirs = ['.testusera', '.testuserb']
    for dir in dirs:
        try:
            shutil.rmtree(dir)
        except FileNotFoundError:
            pass


remove_directories_idempotently()
logging.basicConfig(level=logging.INFO)


class ContrivedInstance:
    def __init__(self, test_dir: str, name: str, email: str):
        self.config = Config()
        self.config.set_value('config_directory', test_dir)
        self.config.set_value('ipfs_directory', os.path.join(test_dir, 'ipfs'))

        self.key_manager = KeyManager(self.config)
        self.user = User(self.key_manager, self.config)
        self.user.bootstrap(name, email)


os.makedirs('.testusera')
os.makedirs('.testuserb')
print('Creating User instances')
instance_a = ContrivedInstance(
    '.testusera', 'User A', 'usera@pillarcloud.org')

instance_b = ContrivedInstance(
    '.testuserb', 'User B', 'userb@pillarcloud.org')


invitation_a = instance_a.user.create_invitation(
    instance_b.user.fingerprint_cid)
instance_b.user.receive_invitation_by_cid(invitation_a)
