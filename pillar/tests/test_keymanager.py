import shutil
from pgpy.constants import PubKeyAlgorithm
from unittest.mock import patch, MagicMock
import os
from ..exceptions import KeyNotVerified, KeyNotInKeyring, \
    CannotImportSamePrimaryFingerprint, WontUpdateToStaleKey
from ..config import PillardConfig
from ..keymanager import KeyManager, KeyOptions, PillarKeyType, PillarPGPKey,\
    SerializingKeyList

import pgpy
from unittest import TestCase, skip


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


def mock_new_pgp_public_key():
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


def load_key_message_from_file(key_path='./data/pubkey0.msgkey'):
    m = pgpy.PGPMessage.from_file(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     key_path))
    return m


def get_deencapsulated_pillar_pgp_key():
    """
    From the valid pillar key loaded from file in mock_pubkey0,
    this convenience function deencapsulates the pgp key from the
    pgp message and returns it.
    """
    keymsg = load_key_message_from_file()
    key, o = pgpy.PGPKey.from_blob(keymsg.message)
    return key


class MockPGPKeyFromFile(MagicMock):
    def __call__(self, *args, **kwargs) -> pgpy.PGPMessage:
        super().__call__(*args, **kwargs)

        return load_key_message_from_file(key_path=self.key_path)


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
    @ patch('pillar.keymanager.KeyManagerInstanceData', new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig(config_directory="/this/shouldnt/exist")
        self.km = KeyManager(self.config, MagicMock(), MagicMock())

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

    @patch('pillar.keymanager.KeyManager.import_peer_key_from_cid',
           new_callable=MagicMock)
    @patch('pillar.keymanager.KeyManager.update_peer_key',
           new_callable=MagicMock)
    def test_import_or_update_peer_key(self, *args):
        fake_cid = 'string'
        self.km.import_or_update_peer_key(fake_cid)
        self.km.import_peer_key_from_cid.assert_called()

    @patch('pillar.keymanager.KeyManager.key_already_in_keyring',
           new_callable=FalseyMock)
    @patch('pillar.keymanager.PillarPGPKey',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.load_pgpy_key',
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
    @ patch('pillar.keymanager.KeyManagerInstanceData', new_callable=MagicMock)
    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey1)
    @patch('pillar.keymanager.PillarPGPKey',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.load_pgpy_key',
           new_callable=MagicMock)
    @patch('pillar.keymanager.PillarPGPKey.load_pgpy_key',
           new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig()

        self.km = KeyManager(self.config, MagicMock(), MagicMock())

        self.km.import_peer_key_from_cid('not_used')

    def test_get_keys_assert_primary(self):
        skl = self.km.get_keys()
        for k in skl:
            assert(k.is_primary)

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey2)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_update_peer_key(self, *args, **kwargs):
        self.km.update_peer_key('not_used')
        self.km.get_key_message_by_cid.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_message_by_cid',
            new_callable=mock_pubkey2)
    @patch('pillar.keymanager.KeyManager.update_peer_key',
           new_callable=MagicMock)
    def test_import_or_update_peer_key(self, *args):
        fake_cid = 'string'
        self.km.import_or_update_peer_key(fake_cid)
        self.km.update_peer_key.assert_called()

    @skip
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
    @patch('pillar.keymanager.KeyManagerInstanceData', new_callable=MagicMock)
    def setUp(self, *args):
        self.config = PillardConfig()
        self.km = KeyManager(self.config, MagicMock(), MagicMock())
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

    @patch('pillar.keymanager.KeyManager.add_key_message_to_ipfs',
           new_callable=MagicMock)
    def test_generate_local_node_subkey(self, *args):
        self.km.generate_local_node_subkey()
        self.km.add_key_message_to_ipfs.assert_called()

    @skip
    @patch('pillar.keymanager.KeyManager.add_key_message_to_ipfs',
           new_callable=MagicMock)
    def test_generate_local_node_subkey_same_node_uuid(self, *args):
        import copy
        orig = copy.copy(self.km.node_uuid)
        self.km.generate_local_node_subkey()
        self.assertEqual(orig, self.km.node_uuid)


@skip
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

    @skip
    def test_import_peers_keys_from_database(self, *args):
        self.km.import_peer_keys_from_database()


def returns_a_list_of_PillarPGPKeys(*args, **kwargs):
    k = PillarPGPKey(MagicMock(), MagicMock())
    k.load_pgpy_key(mock_new_pgp_public_key())
    return [k]


class TestPillarPGPKey(TestCase):
    def setUp(self, *args):
        self.ppgpk = PillarPGPKey(MagicMock(), MagicMock())

    def test_load_pgpy_key(self):
        k = mock_new_pgp_public_key()
        self.ppgpk.load_pgpy_key(k)
        self.assertEqual(k.fingerprint, self.ppgpk.fingerprint)

    @patch('pillar.db.PillarDBObject.load_all_from_db',
           returns_a_list_of_PillarPGPKeys)
    def test_get_keys(self):
        out = PillarPGPKey.get_keys(MagicMock(), MagicMock())
        self.assertTrue(isinstance(out, SerializingKeyList))


class TestNonEmptySerializingKeyList(TestCase):
    def setUp(self):
        self.skl = SerializingKeyList()
        self.key = mock_new_pgp_public_key()
        self.skl.append(self.key)

    def test___delitem__(self):
        self.skl.pop()
        self.assertEqual(len(self.skl), 0)

    def test___getitem__(self):
        k = self.skl.pop()
        assert(isinstance(k, pgpy.PGPKey))
        self.assertEqual(k.fingerprint, self.key.fingerprint)


class TestEmptySerializingKeyList(TestCase):
    def setUp(self):
        self.skl = SerializingKeyList()

    def test_check_raises(self):
        with self.assertRaises(TypeError):
            self.skl.check('')

    def test_check_passes(self):
        self.skl.check(mock_new_pgp_public_key())
        assert(True)

    def test___setitem__(self):
        k = mock_new_pgp_public_key()
        self.skl.append(k)
        self.skl[0] = k
        self.assertEqual(k.fingerprint, self.skl.pop().fingerprint)

    def test_check_raises_for_non_primary(self):
        """
        non-primary keys are disallowed since they can't be deserialized.
        """
        with self.assertRaises(TypeError):
            for o, k in get_deencapsulated_pillar_pgp_key().subkeys.items():
                self.skl.append(k)

    def test___str__(self):
        assert(isinstance(self.skl.__str__(), str))


class TestSerializingKeyListKeyAttrs(TestCase):
    """
    These tests are made to ensure that key attributes remain intact
    throughout the serializing key list's processes.
    Therefore, we use get_deencapsulated_pillar_pgp_key method in this
    class since it contains subkeys.
    """

    def setUp(self):
        self.skl = SerializingKeyList()
        self.key = get_deencapsulated_pillar_pgp_key()
        self.skl.append(self.key)

    def test_metatest_ensure_there_are_subkeys(self):
        assert(len(self.key.subkeys.keys()) > 0)

    def test_subkeys_survive_list(self):
        k = self.skl.pop()
        self.assertEqual(len(k.subkeys.keys()),
                         len(self.key.subkeys.keys()))
