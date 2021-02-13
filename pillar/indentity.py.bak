from .keymanager import KeyManager, PillarKeyType, EncryptionHelper
from .config import Config
from .exceptions import WrongMessageType, WontUpdateToStaleKey
from .ipfs import IPFSClient
from .IPRPC.cid_messenger import CIDMessenger
from .IPRPC.channel import ChannelManager
from .IPRPC.messages import InvitationMessage, FingerprintMessage
from uuid import uuid4
import logging


class LocalIdentity:
    def __init__(self, key_manager: KeyManager,
                 config: Config,
                 cid: str = None):
        self.key_manager = key_manager
        self.config = config
        self.cid = cid
        self.ipfs = IPFSClient()
        self.encryption_helper = EncryptionHelper(
            self.key_manager, self.key_type)
        self.channel_manager = None
        self.start_channel_manager()

    def start_channel_manager(self):
        if self.channel_manager is None:
            self.logger.info('Starting channel manager.')
            key = self.key_manager.load_keytype(self.key_type)
            if key is not None:
                self.channel_manager = ChannelManager(
                    self.encryption_helper, key.fingerprint)

    def receive_invitation_by_cid(self, cid: str):
        self.logger.info(f'Receiving invitation from cid: {cid}')
        invitation = CIDMessenger(
            self.encryption_helper,
            self.config).get_and_decrypt_message_from_cid(cid, verify=False)
        peer_fingerprint = self.key_manager.import_peer_key_from_cid(
            invitation.public_key_cid)
        if not type(invitation) is InvitationMessage:
            raise WrongMessageType(type(invitation))
        with self.key_manager.keyring.key(peer_fingerprint) as key:
            self.channel_manager.add_peer(key, invitation)

    def create_invitation(self, peer_fingerprint_cid):
        fingerprint, pubkey_cid = self._get_info_from_fingerprint_cid(
            peer_fingerprint_cid)
        try:
            self.key_manager.import_or_update_peer_key(pubkey_cid)
        except WontUpdateToStaleKey:
            pass
        invitation = InvitationMessage(
            public_key_cid=pubkey_cid,
            preshared_key=str(uuid4()),
            channels_per_peer=self.config.get_value('channels_per_peer'),
            channel_rotation_period=self.config.get_value('channels_per_peer')
        )
        self.logger.info(
            f'Creating invitation for peer {peer_fingerprint_cid}')
        return CIDMessenger(self.encryption_helper, self.config).\
            add_encrypted_message_to_ipfs_for_peer(invitation, fingerprint)

    def _get_info_from_fingerprint_cid(self, fingerprint_cid):
        self.logger.info(
            f'Getting peer fingerprint info from cid: {fingerprint_cid}')
        fingerprint_info = CIDMessenger(
            self.encryption_helper,
            self.config).get_unencrypted_message_from_cid(fingerprint_cid)
        if not type(fingerprint_info) is FingerprintMessage:
            raise WrongMessageType(type(fingerprint_info))

        return fingerprint_info.fingerprint, fingerprint_info.public_key_cid

    def create_fingerprint_cid(self):
        message = FingerprintMessage(
            public_key_cid=self.key_manager.user_primary_key_cid,
            fingerprint=self.fingerprint)
        return CIDMessenger(
            self.encryption_helper,
            self.config).add_unencrypted_message_to_ipfs(message)


class Node(LocalIdentity):
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('<Node>')
        self.key_type = PillarKeyType.NODE_SUBKEY
        super().__init__(*args, **kwargs)

    def bootstrap(self):
        self.key_manager.generate_local_node_subkey()
        self.cid = self.key_manager.user_primary_key_cid
        self.fingerprint = self.key_manager.node_subkey.fingerprint
        self.fingerprint_cid = self.create_fingerprint_cid()
        self.encryption_helper = EncryptionHelper(
            self.key_manager, self.key_type)
        self.start_channel_manager()
        self.logger.info(
            f'Bootstrapped Node with fingerprint: {self.fingerprint}')


class User(LocalIdentity):
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('<User>')
        self.key_type = PillarKeyType.USER_SUBKEY
        super().__init__(*args, **kwargs)

    def bootstrap(self, name, email):
        self.key_manager.generate_user_primary_key(name, email)
        self.key_manager.generate_local_user_subkey()
        self.cid = self.key_manager.user_primary_key_cid
        self.fingerprint = str(self.key_manager.user_subkey.fingerprint)
        self.fingerprint_cid = self.create_fingerprint_cid()
        self.encryption_helper = EncryptionHelper(
            self.key_manager, self.key_type)
        self.start_channel_manager()
        self.logger.info(
            f'Bootstrapped User with fingerprint: {self.fingerprint}')
