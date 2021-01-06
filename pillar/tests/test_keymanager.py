import pgpy
from unittest import TestCase
from ..keymanager import KeyManager, KeyOptions,\
    CannotImportSamePrimaryFingerprint
from ..config import Config
import os
from unittest.mock import patch, MagicMock
from pgpy.constants import PubKeyAlgorithm


class mock_pgp_public_key1(MagicMock):
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


class mock_pgp_public_key(MagicMock):
    def __call__(self, *args, **kwargs) -> pgpy.PGPKey:
        super().__call__()
        k, o = pgpy.PGPKey.from_file(
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'data/pub.key'))
        return k


class TestKeyManager(TestCase):
    def setUp(self):
        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        self.config = Config(path=configpath)
        self.km = KeyManager(self.config)

    def test_instantiate_keymanager_class(self):
        assert(isinstance(self.km, KeyManager))

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pgp_public_key)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_import_peer_key(self, *args):
        self.km.import_peer_key('notacid')
        self.km.get_key_by_cid.assert_called()
        self.km.ensure_cid_content_present.assert_called()

    @ patch('pillar.keymanager.KeyManager.get_key_by_cid',
            new_callable=mock_pgp_public_key)
    @ patch('pillar.keymanager.KeyManager.ensure_cid_content_present',
            new_callable=MagicMock)
    def test_import_peer_key_twice_raises_exception(self, *args):
        self.km.import_peer_key('notacid')
        with self.assertRaises(CannotImportSamePrimaryFingerprint):
            self.km.import_peer_key('notacid')
