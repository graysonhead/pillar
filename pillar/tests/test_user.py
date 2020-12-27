from unittest import TestCase
import os
from ..config import Config
from ..user import MyUser
from ..tests import AsyncMock
import aioipfs
from unittest.mock import patch, MagicMock
import asyncio
import shutil


class TestMyUser(TestCase):
    def setUp(self):
        """
        users need an ipfs instance and a config.
        We'll mock the necessary methods in ipfs
        and give a valid test config.
        """
        self.loop = asyncio.get_event_loop()
        configpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data/config.yaml')

        ipfs_instance = aioipfs.AsyncIPFS()
        config = Config(path=configpath)
        os.makedirs(os.path.abspath(config.gpghome), exist_ok=True)
        self.name_real = 'notreal'
        self.name_comment = 'nocomment'
        self.name_email = 'noreply@pillarcloud.org'
        self.user = MyUser(config, ipfs_instance)

    def tearDown(self):
        self.loop.run_until_complete(self.user.ipfs.close())
        shutil.rmtree(self.user.config.configdir)

    @patch('pillar.user.MyUser.generate_keypair', new_callable=MagicMock)
    @patch('pillar.user.MyUser.create_primary_pubkey_cid', new_callable=AsyncMock)
    @patch('pillar.user.MyUser._parse_cid', new_callable=AsyncMock)
    def test_bootstrap(self, *args):
        self.loop.run_until_complete(self.user.bootstrap(
            name_real=self.name_real,
            name_comment=self.name_comment,
            name_email=self.name_email))
        self.user.generate_keypair.assert_called_with(
            self.name_real, self.name_comment, self.name_email)
        self.user.create_primary_pubkey_cid.assert_called()
        self.user._parse_cid.assert_called()

    @patch('gnupg.GPG.gen_key', new_callable=MagicMock)
    def test_generate_keypair(self, *args):
        self.user.fingerprint = 'string'
        self.user.generate_keypair(
            self.name_real, self.name_comment, self.name_email)
        self.user.gpg.gen_key.assert_called()
        self.assertEqual(os.path.isfile(self.user.config.pubkey_path), True)

    @patch('aioipfs.api.CoreAPI.add_str', new_callable=AsyncMock)
    def test_create_primary_pubkey_cid(self, *args):
        with open(self.user.config.pubkey_path, 'a+') as f:
            f.write('')

        self.loop.run_until_complete(self.user.create_primary_pubkey_cid())
        self.user.ipfs.core.add_str.assert_called()
        self.assertEqual(self.user.primary_key_cid is not None, True)

    @patch('gnupg.GPG.encrypt', new_callable=MagicMock)
    def test_encrypt_call(self, *args, **kwargs):
        message = MagicMock()
        peer = MagicMock()
        self.user.encrypt_call(message, peer)
        self.user.gpg.encrypt.assert_called()

    @patch('gnupg.GPG.trust_keys', new_callable=MagicMock)
    def test_trust(self, *args, **kwargs):
        peer = MagicMock()
        self.user.trust(peer)
        self.user.gpg.trust_keys.assert_called()
