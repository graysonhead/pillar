from pillar.keymanager import KeyManager
from pillar.config import Config
from pillar.identity import User, Node


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 key_manager: KeyManager):
        self.config = config
        self.key_manager = key_manager

    def run(self):
        user = User(self.key_manager, self.config)
        node = Node(self.key_manager, self.config)
        print(user)
        print(node)
