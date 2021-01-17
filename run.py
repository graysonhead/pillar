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


for k, v in instance_b.key_manager.user_primary_key.subkeys.items():

    peer_b_user_subkey_fingerprint = v.fingerprint

    peer_a_fingerprint = str(
        instance_a.key_manager.user_subkey.pubkey.fingerprint)
    time.sleep(5)
    print('importing keys')
    instance_a.key_manager.import_peer_key(
        instance_b.key_manager.user_primary_key_cid)
    instance_b.key_manager.import_peer_key(
        instance_a.key_manager.user_primary_key_cid)

    encryption_helper_a = EncryptionHelper(
        instance_a.key_manager, PillarKeyType.USER_SUBKEY)
    encryption_helper_b = EncryptionHelper(
        instance_b.key_manager, PillarKeyType.USER_SUBKEY)

    user_a_message = "Pillar is the best cloud!"

    crypt_message_a = encryption_helper_a.\
        sign_and_encrypt_string_to_peer_fingerprint(
            user_a_message,
            peer_b_user_subkey_fingerprint)

    decrypted_message = encryption_helper_b.decrypt_and_verify_encrypted_message(
        crypt_message_a)

    print(decrypted_message)


time.sleep(5)
instance_b.key_manager.generate_local_node_subkey()

instance_a.key_manager.update_peer_key(
    instance_b.key_manager.user_primary_key_cid)
time.sleep(5)
instance_b.key_manager.generate_local_node_subkey()

instance_a.key_manager.update_peer_key(
    instance_b.key_manager.user_primary_key_cid)
