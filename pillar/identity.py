from .keymanager import KeyManager, PillarKeyType, EncryptionHelper
from .config import Config
from .IPRPC.channel import IPRPCChannel
from .IPRPC.messages import IPRPCMessage, IPRPCRegistry
from .IPRPC.cid_message import CIDMessage
from .exceptions import WrongMessageType, WontUpdateToStaleKey
from .ipfs import IPFSClient
from uuid import uuid4
import pgpy
import logging


@IPRPCRegistry.register_rpc_call
class FingerprintMessage(IPRPCMessage):
    attributes = {"public_key_cid": str,
                  "fingerprint": str}


@IPRPCRegistry.register_rpc_call
class InvitationMessage(IPRPCMessage):
    attributes = {"public_key_cid": str,
                  "preshared_key": str,
                  "channels_per_peer": int,
                  "channel_rotation_period": int}


def hash_magic(*args):
    return ["SECRET_CHANNEL"]


class ChannelManager:
    def __init__(self,
                 encryption_helper: EncryptionHelper,
                 local_fingerprint: str):
        self.logger = logging.getLogger('[ChannelManager]')
        self.local_fingerprint = local_fingerprint
        self.encryption_helper = encryption_helper
        self.channels = []

    def add_peer(self, public_key: pgpy.PGPKey, invitation: InvitationMessage):
        self.logger.info(f'Adding peer: {public_key.fingerprint}')
        for fingerprint, subkey in public_key.subkeys.items():
            queue_id_list = hash_magic(
                self.local_fingerprint,
                subkey.fingerprint,
                invitation.preshared_key,
                invitation.channels_per_peer,
                invitation.channel_rotation_period)
            for queue_id in queue_id_list:
                self.channels.append(
                    IPRPCChannel(
                        queue_id,
                        self.local_fingerprint,
                        self.encryption_helper))


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
        invitation = CIDMessage(
            self.encryption_helper,
            self.config).get_and_decrypt_message_from_cid(cid, verify=False)
        peer_fingerprint = self.key_manager.import_peer_key(
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
        return CIDMessage(self.encryption_helper, self.config).\
            add_encrypted_message_to_ipfs_for_peer(invitation, fingerprint)

    def _get_info_from_fingerprint_cid(self, fingerprint_cid):
        self.logger.info(
            f'Getting peer fingerprint info from cid: {fingerprint_cid}')
        fingerprint_info = CIDMessage(
            self.encryption_helper,
            self.config).get_unencrypted_message_from_cid(fingerprint_cid)
        if not type(fingerprint_info) is FingerprintMessage:
            raise WrongMessageType(type(fingerprint_info))

        return fingerprint_info.fingerprint, fingerprint_info.public_key_cid

    def create_fingerprint_cid(self):
        message = FingerprintMessage(
            public_key_cid=self.key_manager.user_primary_key_cid,
            fingerprint=self.fingerprint)
        return CIDMessage(
            self.encryption_helper,
            self.config).add_unencrypted_message_to_ipfs(message)


class Node(LocalIdentity):
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('[Node]')
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
        self.logger = logging.getLogger('[User]')
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
