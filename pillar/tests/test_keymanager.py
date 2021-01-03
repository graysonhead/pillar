from unittest import TestCase
from ..keymanager import KeyManager
from ..config import Config
import os


class TestKeyManager(TestCase):
    def setUp(self):
        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        self.config = Config(path=configpath)

    def test_instantiate_keymanager_class(self):
        km = KeyManager(self.config)
        assert(isinstance(km, KeyManager))
