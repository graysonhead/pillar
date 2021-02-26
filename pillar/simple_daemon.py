from pillar.identity import Node, Primary
from pillar.keymanager import KeyManager, PillarKeyType
from pillar.db import PillarDataStore, PillarDBWorker
from pillar.IPRPC.cid_messenger import CIDMessenger
from pillar.IPRPC.channel import IPRPCChannel
from pillar.ipfs import IPFSWorker
from pillar.config import Config
from pillar.multiproc import PillarWorkerThread, PillarThreadMethodsRegister
import multiprocessing
import signal
import logging


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
#        signal.signal(signal.SIGTERM, self.exit)
        signal.signal(signal.SIGINT, self.exit)
        multiprocessing.Process.__init__(self)
        super().__init__()

    def pre_run(self):
        self.db_worker_instance = PillarDBWorker(self.config)
        self.logger.debug("Starting db worker")
        self.db_worker_instance.start()

        self.pds = PillarDataStore(self.config)

        if self.bootstrapping:
            self.key_manager_instance = KeyManager(self.config)
        else:
            self.key_manager_instance = KeyManager.get_local_instance(
                self.config)

        print(self.key_manager_instance)
        self.logger.debug("Starting key manager")
        self.key_manager_instance.start()

        self.ipfs_worker_instance = IPFSWorker()
        self.logger.debug("Starting ipfs worker")
        self.ipfs_worker_instance.start()
        self.cid_messenger_instance = CIDMessenger(
            PillarKeyType.NODE_SUBKEY,
            self.config)
        self.logger.debug("Starting cid messenger worker")
#        self.cid_messenger_instance.start()

        if self.key_manager_instance.node_subkey is not None and \
           not self.bootstrapping:
            self.node = Node.get_local_instance(self.config)

            self.logger.debug("Starting node")
            self.node.start()
        if self.key_manager_instance.user_primary_key is not None or \
           self.bootstrapping:
            self.primary_worker = Primary(self.config)
            self.logger.debug("Starting user primary worker")
            self.primary_worker.start()
        self.logger.debug("starting fake channel")

        self.channel = IPRPCChannel("id", "fingerprint")
        self.channel.start()

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
