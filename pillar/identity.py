from .multiproc import PillarWorkerThread, PillarThreadMixIn, \
    PillarThreadMethodsRegister, MixedClass
from .db import PillarDBObject, PillarDataStore, NodeIdentity, \
    PrimaryIdentity
from .keymanager import PillarKeyType, EncryptionHelper,\
    KeyManagerCommandQueueMixIn
from .exceptions import WrongMessageType
from .IPRPC.cid_messenger import CIDMessengerMixIn
from .config import PillardConfig
from .IPRPC.channel import ChannelManager
from .IPRPC.messages import InvitationMessage, FingerprintMessage
from uuid import uuid4
import logging
import multiprocessing


class IdentityInterface(KeyManagerCommandQueueMixIn,
                        CIDMessengerMixIn,
                        metaclass=MixedClass):
    pass


class LocalIdentity(PillarDBObject,
                    PillarWorkerThread):
    def __init__(self,
                 config: PillardConfig, start_channel=False):
        self.logger = logging.getLogger(f'<{self.__class__.__name__}>')
        self.public_key_cid = None
        self.config = config
        self.channel_manager = None
        self.cid_messenger_instance = None
        self.id_interface = IdentityInterface()
        super().__init__()

    def start_channel_manager(self):
        if self.channel_manager is None:
            self.logger.info('Starting channel manager.')
            key = self.encryption_helper.local_key
            if key is not None:
                self.channel_manager = ChannelManager(
                    self.encryption_helper, key.fingerprint)
                self.logger.debug('Channel manager started successfully.')

    def pre_run(self):
        self.encryption_helper = EncryptionHelper(self.key_type)

        self.public_key_cid = self.id_interface.key_manager.\
            get_user_primary_key_cid()

    def receive_invitation_by_cid(self, cid: str):
        self.logger.info(f'Receiving invitation from cid: {cid}')
        invitation = self.id_interface.cid_messenger.\
            get_and_decrypt_message_from_cid(cid, verify=False)
        peer_fingerprint = self.id_interface.key_manager.\
            import_peer_key_from_cid(invitation.public_key_cid)
        if not type(invitation) is InvitationMessage:
            raise WrongMessageType(type(invitation))
        key = self.id_interface.key_manager.get_key_from_keyring(
            peer_fingerprint)
        self.channel_manager.add_peer(key, invitation)

    def create_invitation(self, peer_fingerprint_cid):
        fingerprint, pubkey_cid = self._get_info_from_fingerprint_cid(
            peer_fingerprint_cid)

        self.id_interface.key_manager.import_or_update_peer_key(
            pubkey_cid)

        invitation = InvitationMessage(
            public_key_cid=self.public_key_cid,
            preshared_key=str(uuid4()),
            channels_per_peer=self.config.get_value('channels_per_peer'),
            channel_rotation_period=self.config.get_value('channels_per_peer')
        )
        self.logger.info(
            f'Creating invitation for peer {peer_fingerprint_cid}')
        return self.id_interface.cid_messenger.\
            add_encrypted_message_to_ipfs_for_peer(invitation, fingerprint)

    def _get_info_from_fingerprint_cid(self, fingerprint_cid):
        self.logger.info(
            f'Getting peer fingerprint info from cid: {fingerprint_cid}')
        fingerprint_info = self.id_interface.cid_messenger.\
            get_unencrypted_message_from_cid(fingerprint_cid)
        if not type(fingerprint_info) is FingerprintMessage:
            raise WrongMessageType(type(fingerprint_info))

        return fingerprint_info.fingerprint, fingerprint_info.public_key_cid

    def create_fingerprint_cid(self):
        message = FingerprintMessage(
            public_key_cid=self.public_key_cid,
            fingerprint=str(self.fingerprint))
        self.logger.debug(f"created fingerprint cid: {message}")

        return self.id_interface.cid_messenger.add_unencrypted_message_to_ipfs(
            message)

    def create_peer_channels(self):
        for key in self.id_interface.key_manager.get_keys():
            self.channel_manager.add_peer(key)

    @classmethod
    def get_local_instance(cls, config: PillardConfig, pds: PillarDataStore):
        return cls.load_all_from_db([config])[0]


primary_identity_methods = PillarThreadMethodsRegister()


class Primary(LocalIdentity):
    model = PrimaryIdentity
    methods_register = primary_identity_methods
    command_queue = multiprocessing.Queue()
    output_queue = multiprocessing.Queue()
    shutdown_callback = multiprocessing.Event()

    def __init__(self, *args):
        self.key_type = PillarKeyType.USER_PRIMARY_KEY
        multiprocessing.Process.__init__(self)
        super().__init__(*args)

    @ primary_identity_methods.register_method
    def bootstrap(self, name, email):
        self.logger.info("Bootstrapping Primary")
        self.id_interface.key_manager.generate_user_primary_key(name, email)

        self.key = self.id_interface.key_manager.get_private_key_for_key_type(
            self.key_type)
        self.fingerprint = self.key.fingerprint
        self.logger.info(f"User primary fingerprint: {self.fingerprint}")
        self.bootstrap_node()
        self.public_key_cid = self.node.public_key_cid
        self.pds_save()
        self.logger.info('Bootstrap complete.')

    def bootstrap_node(self):
        self.logger.info("Bootstrapping Node")
        self.node = Node(self.config)
        self.id_interface.key_manager.generate_local_node_subkey()

        self.node.fingerprint = self.id_interface.key_manager.\
            get_private_key_for_key_type(
                PillarKeyType.NODE_SUBKEY).pubkey.fingerprint
        self.logger.info(f"Node fingerprint: {self.node.fingerprint}")
        self.node.public_key_cid = self.id_interface.\
            key_manager.get_user_primary_key_cid()
        self.node.fingerprint_cid = self.node.create_fingerprint_cid()
        self.node.pds_save()


class PrimaryIdentityMixIn(PillarThreadMixIn):
    queue_thread_class = Primary
    interface_name = "primary_identity"


class IdentityWithChannel(LocalIdentity):
    def __init__(self, *args, start_channels=False):
        self.start_channels = start_channels
        super().__init__(*args)

    def pre_run(self):
        super().pre_run()
        if self.start_channels:
            self.start_channel_manager()
            self.create_peer_channels()
            self.channel_manager.start_channels()


node_identity_methods = PillarThreadMethodsRegister()


class Node(IdentityWithChannel):
    model = NodeIdentity
    methods_register = node_identity_methods
    command_queue = multiprocessing.Queue()
    output_queue = multiprocessing.Queue()
    shutdown_callback = multiprocessing.Event()

    def __init__(self, *args,
                 id: int = None,
                 fingerprint: str = None,
                 fingerprint_cid: str = None,
                 **kwargs):
        self.id = id
        self.key_type = PillarKeyType.NODE_SUBKEY
        self.fingerprint = fingerprint
        self.fingerprint_cid = fingerprint_cid
        multiprocessing.Process.__init__(self)
        super().__init__(*args)

    @node_identity_methods.register_method
    def get_fingerprint_cid(self):
        return self.fingerprint_cid

    @node_identity_methods.register_method
    def create_invitation(self, *args):
        super().create_invitation(*args)

    def __repr__(self):
        return f"<Node: {self.fingerprint}>"


class NodeIdentityMixIn(PillarThreadMixIn):
    queue_thread_class = Node
    interface_name = "node_identity"
