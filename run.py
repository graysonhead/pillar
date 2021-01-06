from pprint import pprint
from pillar.config import Config
from pillar.keymanager import KeyManager, EncryptionHelper, PeerUser
from pillar.identity import User, Node
from pillar.status import InstanceStatusManager
from pprint import pprint
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
    def __init__(self, configdir: str, name: str, email: str):
        configpath = os.path.join(configdir, 'config.yaml')
        self.config = Config(configpath)
        self.config.privkeydir = configdir
        self.config.configdir = configdir
        self.config.pubkey_path = os.path.join(configdir, 'key.pub')
        self.config.ipfsdir = os.path.join(configdir, 'ipfs')

        self.key_manager = KeyManager(self.config)
        self.status_manger = InstanceStatusManager(self.key_manager)
        self.user = User(self.key_manager)
        self.user.bootstrap(name, email)


test_user_a_path = os.path.join(os.getcwd(), '.testusera')
test_user_b_path = os.path.join(os.getcwd(), '.testuserb')

os.makedirs(test_user_a_path, exist_ok=True)
os.makedirs(test_user_b_path, exist_ok=True)
configpath_a = os.path.join(test_user_a_path, 'config.yaml')
configpath_b = os.path.join(test_user_b_path, 'config.yaml')
with open(configpath_a, 'a+') as f:
    pass

with open(configpath_b, 'a+') as f:
    pass

instance_a = ContrivedInstance(
    test_user_a_path, 'User A', 'usera@pillarcloud.org')

instance_b = ContrivedInstance(
    test_user_b_path, 'User B', 'userb@pillarcloud.org')


for k, v in instance_b.key_manager.user_primary_key.subkeys.items():
    print(k)
    print(v.fingerprint)
    peer_b_user_subkey_fingerprint = v.fingerprint

    pprint(instance_b.key_manager.user_subkey)

    peer_a_fingerprint = str(
        instance_a.key_manager.user_subkey.pubkey.fingerprint)

    instance_a.key_manager.import_peer_key(
        instance_b.key_manager.latest_pubkey_cid)
    instance_b.key_manager.import_peer_key(
        instance_a.key_manager.latest_pubkey_cid)

    encryption_helper_a = EncryptionHelper(instance_a.key_manager)
    encryption_helper_b = EncryptionHelper(instance_b.key_manager)

    user_a_message = "Pillar is the best cloud!"

    crypt_message_a = encryption_helper_a.\
        sign_and_encrypt_string_from_user_subkey_to_peer_fingerprint(
            user_a_message,
            peer_b_user_subkey_fingerprint)

    decrypted_message = encryption_helper_b.decrypt_and_verify_pgp_to_user(
        crypt_message_a)

    print(decrypted_message)


remove_directories_idempotently()
