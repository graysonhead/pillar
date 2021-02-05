from unittest import TestCase
from unittest.mock import MagicMock
from pillar.config import PillardConfig
from pillar.keymanager import KeyManager


class Namespace:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class TestBootstrapKeys(TestCase):

    def setUp(self) -> None:
        self.config = PillardConfig(
            config_directory='pillar/tests/data/bootstrap_test/'
                             'config_dir_empty'
        )
        self.pds = MagicMock
        self.key_manager = KeyManager(self.config)
        self.args = Namespace(purge=False)
