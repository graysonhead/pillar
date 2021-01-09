import pgpy
from unittest import TestCase
from ..keymanager import KeyManager, KeyOptions, WontUpdateToStaleKey, \
    CannotImportSamePrimaryFingerprint, KeyNotInKeyring
from ..config import Config
import os
from unittest.mock import patch, MagicMock
from pgpy.constants import PubKeyAlgorithm


class mock_new_pgp_public_key(MagicMock):
    def __call__(self, *args, **kwargs) -> pgpy.PGPKey:
        super().__call__()

        uid = pgpy.PGPUID.new(
            'Mock User',
            comment='none',
            email='noreply@pillarcloud.org')
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        key.add_uid(uid,
                    usage=KeyOptions.usage,
                    hashes=KeyOptions.hashes,
                    ciphers=KeyOptions.ciphers,
                    compression=KeyOptions.compression)
        return key


class MockPGPKeyFromFile(MagicMock):
    key_path = './data/pub.key'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs) -> pgpy.PGPKey:
        super().__call__()
        k, o = pgpy.PGPKey.from_file(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         self.key_path))
        return k


class mock_pubkey0(MockPGPKeyFromFile):
    key_path = './data/pubkey0.key'


class mock_pubkey1(MockPGPKeyFromFile):
    key_path = './data/pubkey1.key'


class mock_pubkey2(MockPGPKeyFromFile):
    key_path = './data/pubkey2.key'


class TestEmptyKeyManager(TestCase):
    def setUp(self):
        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        self.config = Config(path=configpath)
        self.km = KeyManager(self.config)

    def test_instantiate_keymanager_class(self):
        assert(isinstance(self.km, KeyManager))

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pubkey0)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_import_peer_key(self, *args):
        self.km.import_peer_key('not_used')
        self.km.get_key_by_cid.assert_called()
        self.km.ensure_cid_content_present.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pubkey0)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_import_peer_key_twice_raises_exception(self, *args):
        self.km.import_peer_key('not_used')
        with self.assertRaises(CannotImportSamePrimaryFingerprint):
            self.km.import_peer_key('notacid')

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_new_pgp_public_key)
    def test_update_peer_key_first_raises_exception(self, *args):
        with self.assertRaises(KeyNotInKeyring):
            self.km.update_peer_key('not_used')


class TestNonEmptyKeyManager(TestCase):
    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pubkey1)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def setUp(self, *args):
        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        self.config = Config(path=configpath)
        self.km = KeyManager(self.config)
        self.km.import_peer_key('not_used')

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pubkey2)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_update_peer_key(self, *args, **kwargs):
        self.km.update_peer_key('not_used')
        self.km.get_key_by_cid.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pubkey0)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_update_to_old_peer_key_raises_stale(self, *args, **kwargs):
        with self.assertRaises(WontUpdateToStaleKey):
            self.km.update_peer_key('not_used')
            self.km.get_key_by_cid.assert_called()
