from pillar.config import Config
from pillar.keymanager import KeyManager
from pillar.identity import User
from pillar.db import PillarDataStore
import os
import shutil
import logging


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
        self.config.set_value('db_path', test_dir + 'pillar.db')

        self.ds = PillarDataStore(self.config)
        self.ds.create_database()
        self.key_manager = KeyManager(self.config, self.ds)
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
