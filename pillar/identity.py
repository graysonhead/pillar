from .multiproc import PillarWorkerThread, PillarThreadMixIn, \
    PillarThreadMethodsRegister, MixedClass
from .db import PillarDBObject, NodeIdentity, \
    PrimaryIdentity
from .keymanager import PillarKeyType, EncryptionHelper,\
    KeyManagerCommandQueueMixIn
from .config import PillardConfig

from .exceptions import WrongMessageType
from .IPRPC.cid_messenger import CIDMessengerMixIn
from .IPRPC.channel import ChannelManager
from .IPRPC.messages import InvitationMessage, FingerprintMessage
from uuid import uuid4
import logging
import multiprocessing as mp


class IdentityInterface(KeyManagerCommandQueueMixIn,
                        CIDMessengerMixIn,
                        metaclass=MixedClass):
    pass


class LocalIdentity(PillarDBObject,
                    PillarWorkerThread):
    def __init__(self,
                 config: PillardConfig,
                 command_queue: mp.Queue,
                 output_queue: mp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.logger = logging.getLogger(f'<{self.__class__.__name__}>')
        self.public_key_cid = None
        self.config = config
        self.cid_messenger_instance = None
        self.id_interface = IdentityInterface(str(self),
                                              command_queue=command_queue,
                                              output_queue=output_queue)
        PillarDBObject.__init__(self, self.command_queue, self.output_queue)
        PillarWorkerThread.__init__(self, self.command_queue,
                                    self.output_queue)

    def start_channel_manager(self):
        if self.channel_manager is None:
            self.logger.info('Starting channel manager.')
            key = self.encryption_helper.local_key
            if key is not None:
                self.channel_manager = ChannelManager(
                    self.encryption_helper, key.fingerprint)
                self.logger.debug('Channel manager started successfully.')

    def pre_run(self):
        self.encryption_helper = EncryptionHelper(self.key_type,
                                                  self.command_queue,
                                                  self.output_queue)

        self.public_key_cid = self.id_interface.key_manager.\
            get_user_primary_key_cid()

    def receive_invitation_by_cid(self, cid: str):
        self.logger.info(f'Receiving invitation from cid: {cid}')
        invitation = self.id_interface.cid_messenger.\
            get_and_decrypt_message_from_cid(cid, verify=False)
        if not type(invitation) is InvitationMessage:
            raise WrongMessageType(type(invitation))
        peer_fingerprint = self.id_interface.key_manager.\
            import_or_update_peer_key(invitation.public_key_cid)
#        key = self.id_interface.key_manager.get_key_from_keyring(  # noqa
#            peer_fingerprint)

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

    @classmethod
    def get_local_instance(cls,
                           config: PillardConfig,
                           command_queue: mp.Queue,
                           output_queue: mp.Queue):
        return cls.load_all_from_db(command_queue,
                                    output_queue,
                                    init_args=[config,
                                               command_queue,
                                               output_queue])[0]


primary_identity_methods = PillarThreadMethodsRegister()


class Primary(LocalIdentity):
    model = PrimaryIdentity
    methods_register = primary_identity_methods

    def __init__(self, *args):
        self.key_type = PillarKeyType.USER_PRIMARY_KEY
        mp.Process.__init__(self)
        super().__init__(*args)

    @ primary_identity_methods.register_method
    def bootstrap(self, name, email):
        self.logger.info("Bootstrapping Primary")
        self.id_interface.key_manager.generate_user_primary_key(name, email)

        self.key = self.id_interface.key_manager.get_private_key_for_key_type(
            self.key_type)
        self.fingerprint = self.key.fingerprint
        self.bootstrap_node()
        self.public_key_cid = self.node.public_key_cid
        self.fingerprint_cid = self.create_fingerprint_cid()
        self.pds_save()
        self.logger.info(
            f'Bootstrap complete; node fingerprint: {self.fingerprint}')

    def bootstrap_node(self):
        self.logger.info("Bootstrapping Node")
        self.node = Node(self.config,
                         self.command_queue,
                         self.output_queue)

        key = self.id_interface.key_manager.generate_local_node_subkey()

        self.node.fingerprint = key.fingerprint

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

    def __init__(self, *args,
                 id: int = None,
                 fingerprint: str = None,
                 fingerprint_cid: str = None,
                 **kwargs):
        self.id = id
        self.key_type = PillarKeyType.NODE_SUBKEY
        self.fingerprint = fingerprint
        self.fingerprint_cid = fingerprint_cid
        mp.Process.__init__(self)
        super().__init__(*args)

    @node_identity_methods.register_method
    def get_fingerprint(self):
        return self.fingerprint

    @node_identity_methods.register_method
    def get_fingerprint_cid(self):
        return self.fingerprint_cid

    @node_identity_methods.register_method
    def create_invitation(self, *args):
        return super().create_invitation(*args)

    @node_identity_methods.register_method
    def receive_invitation_by_cid(self, *args):
        return super().receive_invitation_by_cid(*args)

    def __repr__(self):
        return f"<Node: {self.fingerprint}>"


class NodeIdentityMixIn(PillarThreadMixIn):
    queue_thread_class = Node
    interface_name = "node_identity"
