from unittest import TestCase
from ..channel import Channel
from unittest.mock import MagicMock


class TestChannel(TestCase):

    def test_channel_creation(self):
        ipfs_client = MagicMock()
        chan = Channel('test', ipfs_client)
        self.assertEqual('test', chan.queue_id)
