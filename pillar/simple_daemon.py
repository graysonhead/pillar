from pillar.identity import Node, Primary, NodeIdentityMixIn
from pillar.keymanager import KeyManager, PillarKeyType
from pillar.db import PillarDataStore, PillarDBWorker
from pillar.IPRPC.cid_messenger import CIDMessenger
from pillar.ipfs import IPFSWorker
from pillar.config import Config
from pillar.multiproc import PillarWorkerThread, PillarThreadMethodsRegister, \
    PillarThreadMixIn, MixedClass
import multiprocessing
import signal
import logging


class DaemonInterface(NodeIdentityMixIn, metaclass=MixedClass):
    pass


daemon_methods_register = PillarThreadMethodsRegister()


class Daemon(PillarWorkerThread):
    command_queue = multiprocessing.Queue()
    output_queue = multiprocessing.Queue()
    shutdown_callback = multiprocessing.Event()
    methods_register = daemon_methods_register

    def __init__(self,
                 config: Config,
                 bootstrap: bool = False,
                 start_channels: bool = False):
        self.logger = logging.getLogger("<Daemon>")
        self.config = config
        self.bootstrapping = bootstrap
        self.interface = DaemonInterface()
        signal.signal(signal.SIGTERM, self.exit)
        signal.signal(signal.SIGINT, self.exit)
        multiprocessing.Process.__init__(self)
        super().__init__()

    def pre_run(self):
        self.key_manager_instance = KeyManager(self.config)
        self.logger.debug("Starting key manager")
        self.key_manager_instance.start()

        self.ipfs_worker_instance = IPFSWorker(str(self))
        self.logger.debug("Starting ipfs worker")
        self.ipfs_worker_instance.start()
        self.cid_messenger_instance = CIDMessenger(
            PillarKeyType.NODE_SUBKEY,
            self.config)
        self.logger.debug("Starting cid messenger worker")
        self.cid_messenger_instance.start()
        self.db_worker_instance = PillarDBWorker(self.config)
        self.logger.debug("Starting db worker")
        self.db_worker_instance.start()

        if self.key_manager_instance.node_subkey is not None and not self.bootstrapping:
            self.pds = PillarDataStore(self.config)
            self.node = Node.get_local_instance(self.config, self.pds)

            self.logger.debug("Starting node")
            self.node.start()
        if self.key_manager_instance.user_primary_key is not None or self.bootstrapping:
            self.primary_worker = Primary(self.config)
            self.logger.debug("Starting user primary worker")
            self.primary_worker.start()

    def shutdown_routine(self):
        if hasattr(self, "node"):
            self.logger.debug("Stopping node")
            self.node.exit()
        if hasattr(self, "primary_worker"):
            self.logger.debug("Stopping user primary worker")
            self.primary_worker.exit()
        self.logger.debug("Stopping IPFS worker")
        self.ipfs_worker_instance.exit()
        self.logger.debug("Stopping cid messenger worker")
        self.cid_messenger_instance.exit()
        self.logger.debug("Stopping db worker")
        self.db_worker_instance.exit()
        self.logger.debug("Stopping key manager worker")
        self.key_manager_instance.exit()

    @daemon_methods_register.register_method
    def node_create_invitation(self, peer_fingerprint_cid: str):
        return self.interface.node_identity.create_invitation(peer_fingerprint_cid)

    @daemon_methods_register.register_method
    def node_accept_invitation(self, invitation_cid: str):
        return self.interface.node_identity.receive_invitation_by_cid(invitation_cid)

    @daemon_methods_register.register_method
    def get_node_fingerprint_cid(self):
        return self.interface.node_identity.get_fingerprint_cid()


class SimpleDaemonMixIn(PillarThreadMixIn):
    queue_thread_class = Daemon
    interface_name = "daemon"
