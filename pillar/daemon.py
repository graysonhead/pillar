from pillar.keymanager import KeyManager
from pillar.config import Config
from pillar.identity import User
from pillar.db import PillarDataStore


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 key_manager: KeyManager,
                 pds: PillarDataStore):
        self.config = config
        self.key_manager = key_manager
        self.pds = pds

    def run(self):
        users = User.load_all_from_db(self.pds,
                                      init_args=[self.key_manager, self.pds])
        print(users)
