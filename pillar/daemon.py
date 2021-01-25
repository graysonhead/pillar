from pillar.keymanager import KeyManager
from pillar.config import Config
import logging


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 key_manager: KeyManager):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.key_manager = key_manager

    def run(self):
        self.key_manager.start()

    def __repr__(self):
        return "<PillarDaemon>"
