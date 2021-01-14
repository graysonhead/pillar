import pgpy
from unittest import TestCase
from ..keymanager import KeyManager, KeyOptions, PillarKeyType
from ..config import Config
from ..exceptions import KeyNotValidated, KeyNotInKeyring, \
    CannotImportSamePrimaryFingerprint, WontUpdateToStaleKey
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

    def __call__(self, *args, **kwargs) -> pgpy.PGPMessage:
        super().__call__()
        m = pgpy.PGPMessage.from_file(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         self.key_path))
        return m


class mock_pubkey0(MockPGPKeyFromFile):
    key_path = './data/pubkey0.msgkey'


class mock_pubkey1(MockPGPKeyFromFile):
    key_path = './data/pubkey1.msgkey'


class mock_pubkey2(MockPGPKeyFromFile):
    key_path = './data/pubkey2.msgkey'


class mock_invalid_pubkey2(MockPGPKeyFromFile):
    key_path = './data/invalid_pubkey2.msgkey'


class TestEmptyKeyManager(TestCase):
    @ patch('aioipfs.AsyncIPFS', new_callable=MagicMock)
    @ patch('asyncio.get_event_loop', new_callable=MagicMock)
    def setUp(self, *args):
        self.config = Config()
        self.km = KeyManager(self.config)

    def test_instantiate_keymanager_class(self):
        assert(isinstance(self.km, KeyManager))

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey0)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_import_peer_key(self, *args):
        self.km.import_peer_key('not_used')
        self.km.get_key_message_by_cid.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey0)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_import_peer_key_twice_raises_exception(self, *args):
        self.km.import_peer_key('not_used')
        with self.assertRaises(CannotImportSamePrimaryFingerprint):
            self.km.import_peer_key('notacid')

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey0)
    def test_update_peer_key_first_raises_exception(self, *args):
        with self.assertRaises(KeyNotInKeyring):
            self.km.update_peer_key('not_used')


class TestNonEmptyKeyManager(TestCase):
    @ patch('asyncio.get_event_loop', new_callable=MagicMock)
    @ patch('aioipfs.AsyncIPFS', new_callable=MagicMock)
    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey1)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def setUp(self, *args):
        self.config = Config()
        self.km = KeyManager(self.config)
        self.km.import_peer_key('not_used')

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey2)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_update_peer_key(self, *args, **kwargs):
        self.km.update_peer_key('not_used')
        self.km.get_key_message_by_cid.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey0)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_update_to_old_peer_key_raises_stale(self, *args, **kwargs):
        with self.assertRaises(WontUpdateToStaleKey):
            self.km.update_peer_key('not_used')
            self.km.get_key_message_by_cid.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_invalid_pubkey2)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_update_with_invalid_key_raises_exception(self, *args, **kwargs):
        with self.assertRaises(KeyNotValidated):
            self.km.update_peer_key('not_used')
            self.km.get_key_message_by_cid.assert_called()

    def test_load_keytype_no_key(self):
        key = self.km.load_keytype(PillarKeyType.USER_SUBKEY)
        self.assertEqual(key, None)
