from unittest import TestCase
from ..keymanager import KeyManager
from ..config import Config
import os
from unittest.mock import patch, MagicMock
import pgpy


class mock_pgp_public_key(MagicMock):
    def __call__(self, *args, **kwargs) -> pgpy.PGPKey:
        super().__call__()

        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        config = Config(path=configpath)
        config.configdir = './mockdir'
        km = KeyManager(config)
        km.generate_user_primary_key('Mock User', 'noreply@pillarcloud.org')
        return km.user_primary_key


class TestKeyManager(TestCase):
    def setUp(self):
        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        self.config = Config(path=configpath)
        self.km = KeyManager(self.config)

    def test_instantiate_keymanager_class(self):
        assert(isinstance(self.km, KeyManager))

    @patch('pillar.keymanager.KeyManager.get_key_by_cid',
           new_callable=mock_pgp_public_key)
    @patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
           new_callable=MagicMock)
    def test_import_peer_key(self, *args):
        self.km.import_peer_key('notacid')
        self.km.get_key_by_cid.assert_called()
