from pillar.keymanager import KeyManager
from pillar.config import Config


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 key_manager: KeyManager):
        self.config = config
        self.key_manager = key_manager

    def run(self):
        pass
