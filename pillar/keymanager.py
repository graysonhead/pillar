import pgpy
from pgpy.constants import PubKeyAlgorithm, \
    KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy.types import Fingerprint
from .config import Config
import asyncio
from .ipfs import IPFSClient
from .exceptions import KeyNotVerified, KeyNotInKeyring, KeyTypeNotPresent,\
    CannotImportSamePrimaryFingerprint, WontUpdateToStaleKey,\
    MessageCouldNotBeVerified, KeyTypeAlreadyPresent
from pillar.db import PillarDataStore
from enum import Enum, Flag
from uuid import uuid4
import os
import logging


class PillarKeyType(Enum):
    REGISTRATION_PRIMARY_KEY = "REGISTRATION_PRIMARY_KEY"
    USER_PRIMARY_KEY = "USER_PRIMARY_KEY"
    USER_SUBKEY = "USER_SUBKEY"
    NODE_SUBKEY = "NODE_SUBKEY"


class KeyTypes(Flag):
    REGISTRATION = 0x0
    PRIMARY = 0x1
    USER = 0x2
    NODE = 0x4


class KeyManagerStatus(Enum):
    UNREGISTERED = "UNREGISTERED"
    NODE = "NODE"
    USER = "USER"
    PRIMARY = "PRIMARY"
    PRIMARY_NODE = "PRIMARY+NODE"
    PRIMARY_USER = "PRIMARY+USER"
    PRIMARY_NODE_USER = "PRIMARY+NODE+USER"


class KeyOptions:
    usage = {KeyFlags.Sign,
             KeyFlags.EncryptCommunications,
             KeyFlags.EncryptStorage}
    hashes = [HashAlgorithm.SHA256, HashAlgorithm.SHA384,
              HashAlgorithm.SHA512, HashAlgorithm.SHA224]
    ciphers = [SymmetricKeyAlgorithm.AES256,
               SymmetricKeyAlgorithm.AES192,
               SymmetricKeyAlgorithm.AES128]
    compression = [CompressionAlgorithm.ZLIB,
                   CompressionAlgorithm.BZ2,
                   CompressionAlgorithm.ZIP,
                   CompressionAlgorithm.Uncompressed]
    key_expires = None


class KeyManager:
    """
    Keymanager creates and manages the keys needed to operate a
    pillar instance and decrypt messages from peers and maintains
    the keyring used to validate and encrypt messages to peers.
    """

    def __init__(self, config: Config, pds: PillarDataStore):
        self.logger = logging.getLogger('<KeyManager>')
        self.keyring = pgpy.PGPKeyring()
        self.ipfs = IPFSClient()
        self.loop = asyncio.new_event_loop()
        self.config = config
        self.pds = pds
        self.user_primary_key_cid = None
        self.registration_primary_key_cid = None
        self.registration_primary_key = self.load_keytype(
            PillarKeyType.REGISTRATION_PRIMARY_KEY)
        self.user_primary_key = self.load_keytype(
            PillarKeyType.USER_PRIMARY_KEY)
        self.user_subkey = self.load_keytype(PillarKeyType.USER_SUBKEY)
        self.node_subkey = self.load_keytype(PillarKeyType.NODE_SUBKEY)
        self.peer_subkey_map = {}
        self.peer_cid_fingerprint_map = {}
        self.node_uuid = None
        self.import_peer_keys_from_database()

    def get_status(self) -> KeyManagerStatus:
        present_keys = 0x0
        if self.registration_primary_key is not None:
            present_keys |= KeyTypes.REGISTRATION.value
        else:
            if self.user_primary_key is not None:
                present_keys |= KeyTypes.PRIMARY.value
            if self.user_subkey is not None:
                present_keys |= KeyTypes.USER.value
            if self.node_subkey is not None:
                present_keys |= KeyTypes.NODE.value

        if present_keys == KeyTypes.REGISTRATION.value:
            return KeyManagerStatus.UNREGISTERED
        if present_keys == KeyTypes.PRIMARY.value:
            return KeyManagerStatus.PRIMARY
        if present_keys == (KeyTypes.PRIMARY.value | KeyTypes.NODE.value):
            return KeyManagerStatus.PRIMARY_NODE
        if present_keys == (KeyTypes.PRIMARY.value | KeyTypes.USER.value):
            return KeyManagerStatus.PRIMARY_USER
        if present_keys ==\
           (KeyTypes.PRIMARY.value | KeyTypes.NODE.value |
                KeyTypes.USER.value):
            return KeyManagerStatus.PRIMARY_NODE_USER
        if present_keys == KeyTypes.NODE.value:
            return KeyManagerStatus.NODE
        if present_keys == KeyTypes.USER.value:
            return KeyManagerStatus.USER
        if present_keys == (KeyTypes.NODE.value | KeyTypes.USER.value):
            return KeyManagerStatus.NODE_USER
        return KeyManagerStatus.UNREGISTERED

    def is_registered(self) -> bool:
        return self.get_status() != KeyManagerStatus.UNREGISTERED

    def import_peer_key_from_cid(self, cid):
        """
        Import a new key into the keyring from ipfs cid
        """
        peer_key_message = self.get_key_message_by_cid(cid)
        peer_key, other = pgpy.PGPKey.from_blob(peer_key_message.message)
        with open(f'pillar/tests/data/{cid}', 'w+') as f:
            f.write(str(peer_key_message))
        return self.import_peer_key(peer_key)

    def import_peer_keys_from_database(self):
        peer_keys = self.pds.get_keys()
        self.logger.info("Loading peer keys from database")
        for key in peer_keys:
            self.import_peer_key(key, persist=False)

    def import_peer_key(self, peer_key: pgpy.PGPKey, persist=True):
        """
        Import a new key into the keyring
        """
        if self.key_already_in_keyring(peer_key.fingerprint):
            raise CannotImportSamePrimaryFingerprint
        else:
            self.logger.info(
                f"Importing new public key: {peer_key.fingerprint}")
            self.keyring.load(peer_key)
            if persist:
                self.pds.save_key(peer_key)
            for k in peer_key.subkeys:
                self.peer_subkey_map.update(
                    {k: peer_key.fingerprint})
            return peer_key.fingerprint

    def update_peer_key(self, cid):
        """
        update an existing key in the keyring
        """
        new_key_message = self.get_key_message_by_cid(cid)
        try:
            new_key = self.verify_and_extract_key_from_key_message(
                new_key_message)
        except KeyError:
            raise KeyNotInKeyring
        self.logger.info(
            f"Importing peer key: {new_key.fingerprint}")
        if not self.this_key_is_newer(new_key):
            raise WontUpdateToStaleKey
        if not self.this_key_validated_by_original(new_key):
            raise KeyNotVerified

        self.keyring.load(new_key)

    def key_already_in_keyring(self, identifier) -> bool:
        try:
            self.logger.debug(f"checking for key in keyring: {identifier}")
            with self.keyring.key(identifier) as key:
                self.logger.debug(f"Key found: {key.fingerprint}")
                return True
        except KeyError:
            self.logger.debug("Key not found.")
            return False

    def this_key_is_newer(self, key: pgpy.PGPKey) -> bool:
        with self.keyring.key(key.fingerprint) as original_key:
            original_sig = self.get_value_and_requeue(
                original_key._signatures)
            new_sig = self.get_value_and_requeue(key._signatures)
            self.logger.info(f'comparing new key time: {new_sig.created}'
                             f' to old key time: {original_sig.created}')
            if original_sig.created < new_sig.created:
                return True
            else:
                return False

    def this_key_validated_by_original(
            self, key: pgpy.PGPKey) -> pgpy.types.SignatureVerification:
        with self.keyring.key(key.fingerprint) as original_key:
            sig = self.get_value_and_requeue(key._signatures)
            return original_key.pubkey.verify(key,
                                              signature=sig)

    def load_keytype(self, key_type: PillarKeyType):
        try:
            return self.load_private_key_from_file(key_type)
        except KeyTypeNotPresent:
            return None

    def load_private_key_from_file(self,
                                   key_type: PillarKeyType):
        try:
            self.logger.info(f"Loading key type: {key_type.value}")
            path = os.path.join(self.config.get_value('config_directory'),
                                key_type.value)
            key, d = pgpy.PGPKey().from_file(path)
            return key
        except FileNotFoundError:
            raise KeyTypeNotPresent

    def delete_local_keys(self):
        self.logger.info("Deleting local keys")
        for key_type in PillarKeyType:
            try:
                os.remove(os.path.join(
                    self.config.get_value('config_directory'),
                    key_type.value
                          )
                          )
            except FileNotFoundError:
                pass

    def get_key_message_by_cid(self, cid: str) -> pgpy.PGPMessage:
        self.ensure_cid_content_present(cid)
        msg = pgpy.PGPMessage.from_file(
            os.path.join(self.config.get_value('ipfs_directory'), cid))
        return msg

    def verify_and_extract_key_from_key_message(self,
                                                key_message: pgpy.PGPMessage):
        key, other = pgpy.PGPKey.from_blob(str(key_message.message))
        with self.keyring.key(key.fingerprint) as original_key:
            if original_key.verify(key_message):
                return key
            else:
                raise KeyNotVerified

    def ensure_cid_content_present(self, cid: str):
        if not os.path.isfile(
                os.path.join(self.config.get_value('ipfs_directory'), cid)):
            self.logger.info(f"Getting cid from ipfs: {cid}")
            self.loop.run_until_complete(self.ipfs.get_file(
                cid, dstdir=self.config.get_value('ipfs_directory')))

    def generate_primary_key(self, uid: pgpy.PGPUID):
        self.logger.info(f"Generating primary key: {uid}")
        if self.user_primary_key_cid is None:
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
            key.add_uid(uid,
                        usage=KeyOptions.usage,
                        hashes=KeyOptions.hashes,
                        ciphers=KeyOptions.ciphers,
                        compression=KeyOptions.compression)
            key |= key.certify(key)
            self.write_local_privkey(key, PillarKeyType[uid.comment])
            return key
        else:
            raise KeyTypeAlreadyPresent

    def set_registration_primary_key_cid(self, cid):
        self.registration_primary_key_cid = cid

    def set_user_primary_key_cid(self, cid):
        self.user_primary_key_cid = cid

    def generate_registration_primary_key(self):
        uid = pgpy.PGPUID.new(
            uuid4(),
            comment=PillarKeyType.REGISTRATION_PRIMARY_KEY.value,
            email='noreply@pillarcloud.org')
        cid, key = self.generate_primary_key(uid)
        self.set_registration_primary_key_cid(cid)
        self.registration_primary_key_cid = cid
        self.registration_primary_key = self.load_keytype(
            PillarKeyType.REGISTRATION_PRIMARY_KEY)

    def generate_user_primary_key(self, name: str, email: str):
        uid = pgpy.PGPUID.new(name,
                              comment=PillarKeyType.USER_PRIMARY_KEY.value,
                              email=email)
        key = self.generate_primary_key(uid)
        self.user_primary_key = key
        self.load_keytype(
            PillarKeyType.USER_PRIMARY_KEY)
        cid = self.add_key_message_to_ipfs(key.pubkey)
        self.set_user_primary_key_cid(cid)

    def generate_local_user_subkey(self):
        """
        This method creates the initial user subkey during the bootstrap
        process using the user primary key.
        """
        key = self.get_new_user_keypair()

        self.write_local_privkey(
            key, PillarKeyType.USER_SUBKEY)

        self.user_primary_key.add_subkey(
            key,
            usage=KeyOptions.usage)
        self.user_primary_key._signatures.pop()
        self.user_primary_key |= \
            self.user_primary_key.certify(self.user_primary_key)
        cid = self.add_key_message_to_ipfs(self.user_primary_key.pubkey)
        self.set_user_primary_key_cid(cid)
        self.user_subkey = key

    def get_new_user_keypair(self) -> pgpy.PGPKey:
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        key.add_uid(self.user_primary_key.pubkey.userids[0],
                    usage=KeyOptions.usage,
                    hashes=KeyOptions.hashes,
                    ciphers=KeyOptions.ciphers,
                    compression=KeyOptions.compression)
        return key

    def generate_local_node_subkey(self):
        """
        When the user primary key is present, pillar can generate a subkey for
        a local node instance, if needed. Otherwise, the node uuid is created
        with the registration primary key.
        """
        self.node_uuid = str(uuid4())
        key = self.get_new_user_keypair()
        uid = pgpy.PGPUID.new(
            self.node_uuid,
            comment=PillarKeyType.NODE_SUBKEY.value,
            email=self.user_primary_key.pubkey.userids[0].email)

        usage = {KeyFlags.Certify,
                 KeyFlags.Sign,
                 KeyFlags.EncryptCommunications,
                 KeyFlags.EncryptStorage}

        key.add_uid(uid,
                    usage=usage,
                    hashes=KeyOptions.hashes,
                    ciphers=KeyOptions.ciphers,
                    compression=KeyOptions.compression)

        self.write_local_privkey(
            key, PillarKeyType.NODE_SUBKEY)
        self.user_primary_key.add_subkey(
            key,
            usage=KeyOptions.usage)

        self.user_primary_key._signatures.pop()
        self.user_primary_key |= \
            self.user_primary_key.certify(self.user_primary_key)
        cid = self.add_key_message_to_ipfs(self.user_primary_key.pubkey)
        self.set_user_primary_key_cid(cid)
        self.node_subkey = self.load_keytype(
            PillarKeyType.NODE_SUBKEY)

    def write_local_privkey(self, key: pgpy.PGPKey, keytype: PillarKeyType):
        keypath = os.path.join(
            self.config.get_value('config_directory'), keytype.value)
        with open(keypath, 'w+') as f:
            self.logger.warning(f"Writing private key: {keypath}")
            f.write(str(key))

    def add_key_message_to_ipfs(self, key: pgpy.PGPKey):
        message = pgpy.PGPMessage.new(
            str(key), compression=CompressionAlgorithm.Uncompressed)
        message |= self.user_primary_key.sign(message)
        data = self.loop.run_until_complete(self.ipfs.add_str(str(message)))
        self.add_key_to_local_storage(data['Hash'])
        self.logger.info(f"Added pubkey to ipfs: {data['Hash']}")
        self.user_primary_key_cid = data['Hash']
        return data['Hash']

    def add_key_to_local_storage(self, cid: str):
        self.loop.run_until_complete(
            self.ipfs.get_file(cid,
                               dstdir=self.config.get_value('ipfs_directory')))

    @staticmethod
    def get_value_and_requeue(dequeue):
        val = dequeue.pop()
        dequeue.append(val)
        return val


class EncryptionHelper:
    """
    EncryptionHelper provides a simple interface for common encryption
    tasks that involve the use of pillar's other web of trust facilities
    """

    def __init__(self, keymanager: KeyManager):
        self.logger = logging.getLogger(f'[{self.__class__.__name__}]')
        self.key_manager = keymanager

    def sign_and_encrypt_message_from_node_subkey_to_peer_fingerprint(
            self, message: str, peer_fingerprint: str):
        return self._sign_and_encrypt_string_from_local_to_remote(
            message,
            self.key_manager.node_subkey,
            peer_fingerprint)

    def sign_and_encrypt_string_from_user_subkey_to_peer_fingerprint(
            self, message: str, peer_fingerprint: str):
        return self._sign_and_encrypt_string_from_local_to_remote(
            message,
            self.key_manager.user_subkey,
            peer_fingerprint)

    def sign_and_encrypt_string_from_registration_key_to_peer_fingerprint(
            self, message: str, peer_fingerprint: str):
        return self._sign_and_encrypt_string_from_local_to_remote(
            message,
            self.key_manager.registration_primary_key,
            peer_fingerprint)

    def _sign_and_encrypt_string_from_local_to_remote(self,
                                                      message: str,
                                                      local: pgpy.PGPKey,
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
        message |= local.sign(message)
        self.logger.info(f'Ecrypted message for {peer_subkey.fingerprint}')
        return peer_subkey.encrypt(message)

    def decrypt_and_verify_pgp_to_node(self, encrypted_message: str):
        return self._decrypt_and_verify_from_remote_to_local(
            encrypted_message,
            self.key_manager.node_subkey)

    def decrypt_and_verify_pgp_to_user(self, encrypted_message: str):
        return self._decrypt_and_verify_from_remote_to_local(
            encrypted_message,
            self.key_manager.user_subkey)

    def decrypt_and_verify_pgp_to_registration(self, encrypted_message: str):
        return self._decrypt_and_verify_from_remote_to_local(
            encrypted_message,
            self.key_manager.registration_primary_key)

    def _decrypt_and_verify_from_remote_to_local(self,
                                                 encrypted_message: str,
                                                 local: pgpy.PGPKey):
        unverified_message = local.decrypt(encrypted_message)
        self.logger.info(
            f'Decrypted message from {unverified_message.signers}')
        signer = unverified_message.signers.pop()
        signer_parent = self.key_manager.peer_subkey_map[signer]
        with self.key_manager.keyring.key(signer_parent) as peer_pubkey:
            if peer_pubkey.verify(unverified_message):
                verified_message = unverified_message
                self.logger.info("Message verified.")
                return verified_message.message
            else:
                raise MessageCouldNotBeVerified
