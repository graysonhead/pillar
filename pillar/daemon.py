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
        self.users = User.load_all_from_db(
            self.pds,
            init_args=[self.key_manager, self.config])
        self.nodes = Node.load_all_from_db(
            self.pds,
            init_args=[self.key_manager, self.config])
        user = self.users[0]
        user.start_channel_manager()
        user.create_peer_channels()
        user.run()
        self.logger.info(f"Loaded user identities: {self.users}")
        self.logger.info(f"Loaded node identities: {self.nodes}")

    def __repr__(self):
        return "<PillarDaemon>"
