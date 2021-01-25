from .keymanager import PillarKeyType, EncryptionHelper,\
    KeyManagerCommandQueueMixIn
from .config import Config
from .exceptions import WrongMessageType, WontUpdateToStaleKey
from .ipfs import IPFSClient
from .IPRPC.cid_messenger import CIDMessenger
from .IPRPC.channel import ChannelManager
from .IPRPC.messages import InvitationMessage, FingerprintMessage
from .db import PillarDatastoreMixIn, UserIdentity, NodeIdentity
from uuid import uuid4
import logging
from pathos.helpers import mp as multiprocessing


class LocalIdentity(multiprocessing.Process,
                    KeyManagerCommandQueueMixIn,
                    PillarDatastoreMixIn):
    def __init__(self,
                 config: Config,
                 *args):
        self.public_key_cid = None
        self.config = config
        self.ipfs = IPFSClient()
        self.channel_manager = None
        multiprocessing.Process.__init__(self)
        KeyManagerCommandQueueMixIn.__init__(self, *args)

    def start_channel_manager(self):
        if self.channel_manager is None:
            self.logger.info('Starting channel manager.')
            key = self.local_key = self.key_manager_command(
                "get_private_key_for_key_type",
                self.key_type)
            if key is not None:
                self.channel_manager = ChannelManager(
                    self.encryption_helper, key.fingerprint)

    def run(self):
        self.encryption_helper = EncryptionHelper(
            self.key_type,
            self.manager_command_queue,
            self.manager_output_queue,
            self.shutdown_callback)

        self.start_channel_manager()
        self.public_key_cid = self.key_manager_command(
            "get_user_primary_key_cid")

        self.create_peer_channels()
        self.channel_manager.start_channels()

    def receive_invitation_by_cid(self, cid: str):
        self.logger.info(f'Receiving invitation from cid: {cid}')
        invitation = CIDMessenger(
            self.encryption_helper,
            self.config).get_and_decrypt_message_from_cid(cid, verify=False)
        peer_fingerprint = self.key_manager_command(
            "import_peer_key_from_cid",
            invitation.public_key_cid)
        if not type(invitation) is InvitationMessage:
            raise WrongMessageType(type(invitation))
        key = self.key_manager_command(
            "get_key_from_keyring",
            peer_fingerprint)
        self.channel_manager.add_peer(key, invitation)

    def create_invitation(self, peer_fingerprint_cid):
        fingerprint, pubkey_cid = self._get_info_from_fingerprint_cid(
            peer_fingerprint_cid)
        try:
            self.key_manager_command("import_or_update_peer_key",
                                     pubkey_cid)
        except WontUpdateToStaleKey:
            pass
        invitation = InvitationMessage(
            public_key_cid=self.public_key_cid,
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
            public_key_cid=self.key_manager_command(
                "get_user_primary_key_cid"),
            fingerprint=str(self.fingerprint))
        return CIDMessenger(
            self.encryption_helper,
            self.config).add_unencrypted_message_to_ipfs(message)

    def create_peer_channels(self):
        for key in self.key_manager_command("get_keys"):
            self.channel_manager.add_peer(key)


class Node(LocalIdentity):
    model = NodeIdentity

    def __init__(self, *args,
                 id: int = None,
                 fingerprint: str = None,
                 fingerprint_cid: str = None,
                 **kwargs):
        self.id = id
        self.logger = logging.getLogger('<Node>')
        self.key_type = PillarKeyType.NODE_SUBKEY
        self.fingerprint = fingerprint
        self.fingerprint_cid = fingerprint_cid
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<Node: {self.fingerprint}>"

    def bootstrap(self):
        self.key_manager.generate_local_node_subkey()
        self.public_key_cid = self.key_manager_command(
            "get_user_primary_key_cid"),
        self.key = self.key_manager_command("get_private_key_for_key_type",
                                            self.key_type)
        self.fingerprint = self.key.fingerprint
        self.fingerprint_cid = self.create_fingerprint_cid()

        self.start_channel_manager()
        self.logger.info(
            f'Bootstrapped Node with fingerprint: {self.fingerprint}')


class User(LocalIdentity):
    model = UserIdentity

    def __init__(self, *args,
                 id: int = None,
                 fingerprint: str = None,
                 fingerprint_cid: str = None,
                 **kwargs):
        self.id = id
        self.logger = logging.getLogger('<User>')
        self.key_type = PillarKeyType.USER_SUBKEY
        self.fingerprint = fingerprint
        self.fingerprint_cid = fingerprint_cid
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"<User: {self.fingerprint}>"

    def bootstrap(self, name, email):
        self.key_manager_command("generate_user_primary_key", name, email)
        self.key_manager_command("generate_user_subkey")
        self.public_key_cid = self.key_manager_command(
            "get_user_primary_key_cid"),
        self.key = self.key_manager_command("get_private_key_for_key_type",
                                            self.key_type)
        self.fingerprint = self.key.fingerprint
        self.fingerprint_cid = self.create_fingerprint_cid()
        self.start_channel_manager()
        self.logger.info(
            f'Bootstrapped User with fingerprint: {self.fingerprint}')
