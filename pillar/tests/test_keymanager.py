import shutil
from pgpy.constants import PubKeyAlgorithm
from unittest.mock import patch, MagicMock
import os
from ..exceptions import KeyNotVerified, KeyNotInKeyring, \
    CannotImportSamePrimaryFingerprint, WontUpdateToStaleKey
from ..config import PillardConfig
from ..keymanager import KeyManager, KeyOptions, PillarKeyType

import pgpy
from unittest import TestCase


def remove_directories(dirs: list):
    for dir in dirs:
        try:
            shutil.rmtree(dir)
        except FileNotFoundError:
            pass


class TruthyMock(MagicMock):
    def __call__(self, *args, **kwargs) -> bool:
        super().__call__(*args, **kwargs)
        return True


class FalseyMock(MagicMock):
    def __call__(self, *args, **kwargs) -> bool:
        super().__call__(*args, **kwargs)
        return False


class mock_new_pgp_public_key(MagicMock):
    def __call__(self, *args, **kwargs) -> pgpy.PGPKey:
        super().__call__(*args, **kwargs)

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

    def __call__(self, *args, **kwargs) -> pgpy.PGPMessage:
        super().__call__(*args, **kwargs)
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
    @ patch('pillar.identity.Node', new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig(config_directory="/this/shouldnt/exist")
        self.km = KeyManager(self.config)
        self.km.start()

    def test_instantiate_keymanager_class(self):
        assert(isinstance(self.km, KeyManager))

    @patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
           new_callable=mock_pubkey0)
    @patch('pillar.keymanager.KeyManager.import_peer_key',
           new_callable=MagicMock)
    def test_import_peer_key_from_cid(self, *args):
        key = mock_pubkey0()
        fake_cid = 'himom'
        self.km.import_peer_key_from_cid(fake_cid)
        self.km.get_key_message_by_cid.assert_called_with(fake_cid)
        self.km.import_peer_key.assert_called_with(key)

    @patch('pillar.keymanager.KeyManager.key_already_in_keyring',
           new_callable=FalseyMock)
    @patch('pillar.keymanager.PillarPGPKey',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.load_pgpy_key',
           new_callable=MagicMock)
    def test_import_peer_key(self, *args):

        keyfunction = mock_pubkey0()
        key, o = pgpy.PGPKey.from_blob(keyfunction().message)

        self.km.import_peer_key(key)
        self.km.key_already_in_keyring.assert_called_with(key.fingerprint)

    @patch('pillar.keymanager.KeyManager.key_already_in_keyring',
           new_callable=TruthyMock)
    @patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
           new_callable=mock_pubkey0)
    def test_import_peer_key_raises_exception(self, *args):

        keyfunction = mock_pubkey0()
        key, o = pgpy.PGPKey.from_blob(keyfunction().message)

        with self.assertRaises(CannotImportSamePrimaryFingerprint):
            self.km.import_peer_key(key)

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
    @patch('pillar.keymanager.PillarPGPKey',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.load_pgpy_key',
           new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig()
        self.km = KeyManager(self.config)
        self.km.import_peer_key_from_cid('not_used')

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
            noew_callable=MagicMock)
    def test_update_with_invalid_key_raises_exception(self, *args, **kwargs):
        with self.assertRaises(KeyNotVerified):
            self.km.update_peer_key('not_used')
            self.km.get_key_message_by_cid.assert_called()

    def test_load_keytype_no_key(self):
        key = self.km.load_keytype(PillarKeyType.NODE_SUBKEY)
        self.assertEqual(key, None)

    def test_this_key_is_newer_or_equal(self):
        keymsg = mock_pubkey2()
        key, o = pgpy.PGPKey.from_blob(keymsg().message)
        assert(self.km.this_key_is_newer_or_equal(key))

    def test_this_key_validated_by_original(self):
        keymsg = mock_pubkey2()
        key, o = pgpy.PGPKey.from_blob(keymsg().message)
        if not self.km.this_key_validated_by_original(key):
            assert(False)


class TestKeyManagerSubkeyGeneration(TestCase):
    @ patch('pillar.keymanager.KeyManager.add_key_message_to_ipfs',
            new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.load_pgpy_key',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.pds_save',
           new_callable=MagicMock)
    @patch('pillar.keymanager.KeyManager.pds_save',
           new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig()
        self.km = KeyManager(self.config)
        self.km.start()
        self.config.set_value('config_directory', '.unittestconfigdir')
        dir = self.config.get_value('config_directory')
        if not os.path.exists(dir):
            os.makedirs(self.config.get_value('config_directory'))
        self.km.generate_user_primary_key("name", "email")

    def tearDown(self):
        remove_directories([self.config.get_value('config_directory')])
        self.km.exit()
        self.km.join()

    @patch('pillar.keymanager.KeyManager.pds_save',
           new_callable=MagicMock)
    @patch('pillar.keymanager.KeyManager.add_key_message_to_ipfs',
           new_callable=MagicMock)
    def test_generate_local_node_subkey(self, *args):
        self.km.generate_local_node_subkey()
        self.km.add_key_message_to_ipfs.assert_called()

    def test_get_status_with_primary_key_present(self, *args):
        status = self.km.get_status()
        self.assertEqual(status, KeyManagerStatus.PRIMARY)


class TestKeyManagerDBOperations(TestCase):
    @patch('aioipfs.AsyncIPFS', new_callable=MagicMock)
    @patch('asyncio.get_event_loop', new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig()
        self.km = KeyManager(self.config)

    @patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
           new_callable=mock_pubkey0)
    @patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
           new_callable=MagicMock)
    def test_import_peer_key_saves_to_database(self, *args):
        self.km.import_peer_key_from_cid('not_used')
        self.km.get_key_message_by_cid.assert_called()

    def test_import_peers_keys_from_database(self, *args):
        self.km.import_peer_keys_from_database()
