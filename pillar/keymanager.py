import pgpy
from pgpy.constants import PubKeyAlgorithm, \
    KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from pgpy.types import Fingerprint
from .config import Config
import asyncio
import aioipfs
from enum import Enum
import os
import logging
from pprint import pprint


class Peer:
    def __init__(self, cid: str):
        self.primary_key_fingerprint = None
        self.subkey_fingerprint = None
        self.peer_listen_channels = []
        self.cid = cid


class PeerUser(Peer):
    """
    PeerUser represents an instance of User running on another pillar
    instance.
    """


class PeerNode(Peer):
    """
    A remote instance of pillar that's running an instance of Node. Nodes
    may provide a resource of some kind to the pillar cloud. As with the
    local Node instance, a PeerNode has similar structure to its User
    counterpart, but has a different set of capabilities.
    """


class KeyTypeNotPresent(Exception):
    """
    Raised when trying to load a key type which isnt present on the
    instance.
    """


class KeyNotInKeyring(Exception):
    """
    Raised when attemting to update a key with one that's not already
    in the keyring.
    """


class WontUpdateToStaleKey(Exception):
    """
    Raised when attemting to update a key with one that is stale.
    """


class MessageCouldNotBeVerified(Exception):
    """
    Raised when a message signature cannot be verified.
    """


class KeyNotValidated(Exception):
    """
    Raised when attemting to update a key with one that is not validated
    by an existing key in the keyring.
    """


class CannotImportSamePrimaryFingerprint(Exception):
    """
    Raised in import_peer_key if an attempt is made to import a key whose
    primary fingerprint is already known to the key manager. update_peer_key
    should be used in that case instead.
    """


class KeyTypeAlreadyPresent(Exception):
    """
    Raised when trying to generate a primary key type that already exists on
    this node. I.e.: you can't make another user primary key if you already
    have one. Same goes for the registration primary. Delete first, then
    proceed if that's what you want.
    """


class PillarKeyType(Enum):
    REGISTRATION_PRIMARY_KEY = "REGISTRATION_PRIMARY_KEY"
    USER_PRIMARY_KEY = "USER_PRIMARY_KEY"
    USER_SUBKEY = "USER_SUBKEY"
    NODE_SUBKEY = "NODE_SUBKEY"


class PillarPrivKey:
    def __init__(self, config: Config, key_type: PillarKeyType):
        self.config = config
        self.logger = logging.getLogger(f'[{self.__class__.__name__}]')
        self.logger.info("Loading key.")
        self.path = os.path.join(config.privkeydir, key_type.value)
        self.key, *d = pgpy.PGPKey().from_file(self.path)
        self.key_type = key_type


class KeyOptions:
    usage = {KeyFlags.Certify,
             KeyFlags.Sign,
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

    def __init__(self, config: Config):
        self.logger = logging.getLogger('[KeyManager]')
        self.keyring = pgpy.PGPKeyring()
        self.ipfs = aioipfs.AsyncIPFS()
        self.loop = asyncio.get_event_loop()
        self.config = config
        self.registration_primary_key = self.load_keytype(
            PillarKeyType.USER_PRIMARY_KEY)
        self.user_primary_key = self.load_keytype(
            PillarKeyType.USER_PRIMARY_KEY)
        self.user_subkey = self.load_keytype(PillarKeyType.USER_SUBKEY)
        self.node_subkey = self.load_keytype(PillarKeyType.NODE_SUBKEY)
        self.latest_pubkey_cid = None
        self.peer_subkey_map = {}

    def import_peer_key(self, cid):
        """
        Import a new key into the keyring
        """
        self.ensure_cid_content_present(cid)
        peer_key = self.get_key_by_cid(cid)

        if self.key_already_in_keyring(peer_key.fingerprint):
            raise CannotImportSamePrimaryFingerprint
        else:
            self.logger.info(
                f"Importing new public key: {peer_key.fingerprint}")
            self.keyring.load(peer_key)
            for k in peer_key.subkeys:
                self.peer_subkey_map.update(
                    {k: peer_key.fingerprint})
            return peer_key.fingerprint

    def update_peer_key(self, cid):
        """
        update an existing key in the keyring
        """
        new_key = self.get_key_by_cid(cid)
        self.logger.info(
            f"Importing peer key: {new_key.fingerprint}")
        if not self.key_already_in_keyring(new_key.fingerprint):
            raise KeyNotInKeyring
        if not self.this_key_is_newer(new_key):
            raise WontUpdateToStaleKey
        if not self.this_key_validated_by_original(new_key):
            raise KeyNotValidated

        self.keyring.load(new_key)

    def key_already_in_keyring(self, identifier) -> bool:
        try:
            self.logger.debug(f"checking for key in keyring: {identifier}")
            key = self.keyring._get_key(identifier)
            self.logger.debug(f"Key found: {key.fingerprint}")
            return True
        except KeyError:
            return False

    def this_key_is_newer(self, key: pgpy.PGPKey) -> bool:
        original_key = self.keyring.key(key.fingerprint)
        if original_key.created < key.created:
            return True
        else:
            return False

    def this_key_validated_by_original(
            self, key: pgpy.PGPKey) -> pgpy.types.SignatureVerification:
        original_key = self.keyring.key(key.fingerprint)
        return original_key.verify(key)

    def load_keytype(self, key_type: PillarKeyType):
        try:
            self.ensure_key_type_ipfs_content_present(key_type)
            return self.load_private_key_from_file(key_type)
        except KeyTypeNotPresent:
            return None

    def load_private_key_from_file(self, key_type: PillarKeyType):
        self.logger.info(f"Loading key type: {key_type.value}")
        path = os.path.join(self.config.privkeydir, key_type.value)
        key, d = pgpy.PGPKey().from_file(path)
        return key

    def key_not_present(self, key_type: PillarKeyType) -> bool:
        cid = self.get_cid_for_key_type(key_type)
        if cid is None:
            return True
        else:
            return False

    def ensure_key_type_ipfs_content_present(self, key_type: PillarKeyType):
        cid = self.get_cid_for_key_type(key_type)
        if cid is None:
            raise KeyTypeNotPresent
        else:
            self.ensure_cid_content_present(cid)

    def get_key_by_cid(self, cid: str) -> pgpy.PGPKey:
        self.ensure_cid_content_present(cid)
        key, o = pgpy.PGPKey.from_file(os.path.join(self.config.ipfsdir, cid))
        return key

    def ensure_cid_content_present(self, cid: str):
        if not os.path.isfile(os.path.join(self.config.ipfsdir, cid)):
            self.logger.info(f"Getting cid from ipfs: {cid}")
            self.loop.run_until_complete(self.ipfs.get(
                cid, dstdir=self.config.ipfsdir))

    def get_cid_for_key_type(self, key_type: PillarKeyType) -> str:
        """gets the cid from the config for the given key type"""
        config_item_map = {
            PillarKeyType.REGISTRATION_PRIMARY_KEY:
                self.config.registration_primary_key_cid,
            PillarKeyType.USER_PRIMARY_KEY: self.config.user_primary_key_cid,
            PillarKeyType.USER_SUBKEY: self.config.user_subkey_cid,
            PillarKeyType.NODE_SUBKEY: self.config.node_subkey_cid}
        return config_item_map[key_type]

    def generate_primary_key(self, uid: pgpy.PGPUID):
        self.logger.info(f"Generating primary key: {uid}")
        if self.key_not_present(PillarKeyType[uid.comment]):
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
            key.add_uid(uid,
                        usage=KeyOptions.usage,
                        hashes=KeyOptions.hashes,
                        ciphers=KeyOptions.ciphers,
                        compression=KeyOptions.compression)
            self.add_key_to_ipfs(key.pubkey)
            self.write_local_privkey(key, PillarKeyType[uid.comment])
            return self.add_key_to_ipfs(key.pubkey)
        else:
            raise KeyTypeAlreadyPresent

    def generate_registration_primary_key(self):
        uid = pgpy.PGPUID.new(
            self.config.node_id,
            comment=PillarKeyType.REGISTRATION_PRIMARY_KEY.value,
            email='noreply@pillarcloud.org')
        cid = self.generate_primary_key(uid)
        self.config.registration_primary_key_cid = cid
        self.config.save()
        self.registration_primary_key = self.load_keytype(
            PillarKeyType.REGISTRATION_PRIMARY_KEY)

    def generate_user_primary_key(self, name: str, email: str):
        uid = pgpy.PGPUID.new(name,
                              comment=PillarKeyType.USER_PRIMARY_KEY.value,
                              email=email)
        cid = self.generate_primary_key(uid)
        self.config.user_primary_key_cid = cid
        self.config.save()
        self.user_primary_key = self.load_keytype(
            PillarKeyType.USER_PRIMARY_KEY)

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
        cid = self.add_key_to_ipfs(self.user_primary_key.pubkey)
        self.config.user_subkey_cid = cid
        self.config.save()
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
        key = self.generate_node_subkey()
        cid = self.add_key_to_ipfs(self.user_primary_key.pubkey)
        self.config.node_subkey_cid = cid
        self.config.save()
        self.write_local_privkey(
            key, PillarKeyType.NODE_SUBKEY)
        self.node_subkey = self.load_keytype(
            PillarKeyType.NODE_SUBKEY)

    def generate_node_subkey(self):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        usageflags = {KeyFlags.EncryptStorage,
                      KeyFlags.EncryptCommunications}
        uid = pgpy.PGPUID.new(self.config.node_uuid,
                              comment=PillarKeyType.NODE_SUBKEY.value,
                              email=self.user_primary_key.pubkey.email)
        key.add_uid(uid, usage=usageflags)
        self.user_primary_key.add_subkey(
            key,
            usage=usageflags)
        self.logger.info(f"Created node subkey: {key.fingerprint}")
        return key

    def write_local_privkey(self, key: pgpy.PGPKey, keytype: PillarKeyType):
        keypath = os.path.join(self.config.privkeydir, keytype.value)
        with open(keypath, 'w+') as f:
            self.logger.warn(f"Writing private key: {keypath}")
            f.write(str(key))

    def add_key_to_ipfs(self, key: pgpy.PGPKey):
        data = self.loop.run_until_complete(self.ipfs.add_str(str(key)))
        self.add_key_to_local_storage(data['Hash'])
        self.logger.info(f"Added pubkey to ipfs: {data['Hash']}")
        self.latest_pubkey_cid = data['Hash']
        return data['Hash']

    def add_key_to_local_storage(self, cid: str):
        self.loop.run_until_complete(self.ipfs.get(cid,
                                                   dstdir=self.config.ipfsdir))


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
        print(self.key_manager.peer_subkey_map)
        remote_keyid = Fingerprint.__new__(
            Fingerprint, remote_fingerprint).keyid
        parent_fingerprint = \
            self.key_manager.peer_subkey_map[remote_keyid]
        with self.key_manager.keyring.key(parent_fingerprint) as peer_key:
            peer_subkey = None
            pprint(peer_key.__dict__)
            pprint(peer_key._children.__class__)
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
