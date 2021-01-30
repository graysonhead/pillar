from pillar.keymanager import KeyManager
from pillar.config import Config
from pillar.ipfs import IPFSWorker
import logging


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 key_manager: KeyManager):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.key_manager = key_manager
        self.ipfs_workers = self.get_ipfs_workers(self.config)

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

    def run(self):
        self.start_ipfs_workers()
        self.key_manager.start()

    def __del__(self):
        self.stop_ipfs_workers()

    def __repr__(self):
        return "<PillarDaemon>"
