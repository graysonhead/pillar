import pgpy
from pgpy.types import Fingerprint
from .exceptions import MessageCouldNotBeVerified, InvalidKeyType
from .keymanager import PillarKeyType, KeyManager
import logging


class EncryptionHelper:
    """
    EncryptionHelper provides a simple interface for common encryption
    tasks that involve the use of pillar's other web of trust facilities
    """

    def __init__(self, keymanager: KeyManager, keytype: PillarKeyType):
        self.logger = logging.getLogger(f'[{self.__class__.__name__}]')
        self.key_manager = keymanager
        self.keytype = keytype
        if self.keytype == PillarKeyType.NODE_SUBKEY:
            self.local_key = self.key_manager.node_subkey
        elif self.keytype == PillarKeyType.USER_SUBKEY:
            self.local_key = self.key_manager.user_subkey
        elif self.keytype == PillarKeyType.REGISTRATION_PRIMARY_KEY:
            self.local_key = self.key_manager.registration_primary_key
        else:
            raise InvalidKeyType(keytype)

    def sign_and_encrypt_string_to_peer_fingerprint(self,
                                                    message: str,
                                                    remote_fingerprint: str):
        remote_keyid = Fingerprint.__new__(
            Fingerprint, remote_fingerprint).keyid
        parent_fingerprint = self.key_manager.peer_subkey_map[remote_keyid]
        with self.key_manager.keyring.key(parent_fingerprint) as peer_key:
            peer_subkey = None
            for _, key in peer_key._children.items():
                if key.fingerprint == remote_fingerprint:
                    peer_subkey = key
                    break

        message = pgpy.PGPMessage.new(message)
        message |= self.local_key.sign(message)
        self.logger.info(f'Encrypted message for {peer_subkey.fingerprint}')
        return peer_subkey.encrypt(message)

    def decrypt_and_verify_encrypted_message(self,
                                             encrypted_message: str,
                                             verify: bool = True):
        msg = pgpy.PGPMessage.from_blob(encrypted_message)
        unverified_message = self.local_key.decrypt(msg)
        self.logger.info(
            f'Decrypted message from {unverified_message.signers}')
        if not verify:
            return unverified_message

        signer = unverified_message.signers.pop()
        signer_parent = self.key_manager.peer_subkey_map[signer]
        with self.key_manager.keyring.key(signer_parent) as peer_pubkey:
            if peer_pubkey.verify(unverified_message):
                verified_message = unverified_message
                self.logger.info("Message verified.")
                return verified_message.message
            else:
                raise MessageCouldNotBeVerified
