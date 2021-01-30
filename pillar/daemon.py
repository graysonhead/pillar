from pillar.keymanager import KeyManager
from pillar.config import Config
from pillar.ipfs import IPFSWorker
from pillar.identity import Node
from pillar.daemon3x import daemon
from pillar.db import PillarDataStore
import logging
import time


class PillarDaemon(daemon):

    def __init__(self,
                 config: Config,
                 *args,
                 **kwargs):
        self.config = config
        self.pds = PillarDataStore(self.config)
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(self.__repr__())

    def start_ipfs_workers(self):
        for worker in self.ipfs_workers:
            worker.start()

    def stop_ipfs_workers(self):
        for worker in self.ipfs_workers:
            worker.exit()

    def get_ipfs_workers(self, config: Config):
        workers = []
        for i in range(config.get_value('ipfs_workers')):
            workers.append(IPFSWorker(str(i)))
        return workers

    def stop_child_procs(self):
        self.logger.info("stopping node.")
        self.node.exit()
        self.logger.info("stopping key manager.")
        self.key_manager.exit()
        self.logger.info("stopping ipfs workers.")
        self.stop_ipfs_workers()
        self.shutdown_callback.set()

    def hodor(self):
        while not self.shutdown_callback.is_set():
            time.sleep(0.1)
        self.logger.info("daemon stopped.")

    def run(self):
        self.key_manager = KeyManager(self.config, self.pds)
        self.node = Node(self.config)
        self.ipfs_workers = self.get_ipfs_workers(self.config)
        self.logger.info("Starting IPFS workers")
        self.start_ipfs_workers()
        self.logger.info("Starting key manager worker")
        self.key_manager.start()
        self.logger.info("Starting node worker")
        self.node.start()
        self.hodor()

    def __repr__(self):
        return "<PillarDaemon>"
