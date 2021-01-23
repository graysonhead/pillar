from pillar.keymanager import KeyManager
from pillar.config import Config
from pillar.identity import User, Node
from pillar.db import PillarDataStore
import logging


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 key_manager: KeyManager,
                 pds: PillarDataStore):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.key_manager = key_manager
        self.pds = pds
        self.users = []
        self.nodes = []

    def run(self):
        try:
            self.user = User(self.key_manager, self.config, self.pds)
            self.user.start_channel_manager()
            self.user.create_peer_channels()
            self.user.run()
            self.logger.info(f"Running user daemon: {self.user}")
        except Exception:
            pass
        try:
            self.node = Node(self.key_manager, self.config, self.pds)
            self.node.start_channel_manager()
            self.node.create_peer_channels()
            self.node.run()
            self.logger.info(f"Running node daemon: {self.user}")
        except Exception as e:
            raise e

    def __repr__(self):
        return "<PillarDaemon>"
