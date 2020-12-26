from unittest import TestCase
import os
from ..config import Config
from ..user import MyUser
from ..tests import AsyncMock
import aioipfs
from unittest.mock import patch, MagicMock
import asyncio


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
        self.user = MyUser(config, ipfs_instance)

    def tearDown(self):
        self.loop.run_until_complete(self.user.ipfs.close())

    @patch('pillar.user.MyUser.generate_keypair', new_callable=MagicMock)
    @patch('pillar.user.MyUser.create_pubkey_cid', new_callable=AsyncMock)
    @patch('pillar.user.MyUser._parse_cid', new_callable=AsyncMock)
    def test_bootstrap(self, *args):
        self.loop.run_until_complete(self.user.bootstrap())
        self.user.generate_keypair.assert_called()
        self.user.create_pubkey_cid.assert_called()
        self.user._parse_cid.assert_called()
