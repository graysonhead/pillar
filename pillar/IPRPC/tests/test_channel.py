from unittest import TestCase
from ..channel import CallChannel
from unittest.mock import MagicMock
import aioipfs
import asyncio
import logging

logging.basicConfig(level=logging.ERROR)


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


class TestCallChannel(TestCase):

    def test_channel_id(self):
        chan = CallChannel('test_queue',
                           MagicMock())
        self.assertEqual('test_queue', chan.queue_id)

    def test_channel_queue_send_message(self):
        ipfs_instance = aioipfs.AsyncIPFS()
        ipfs_instance.pubsub = AsyncMock()
        chan = CallChannel('test_queue',
                           ipfs_instance)
        test_string = "This is a test message"

        loop = asyncio.get_event_loop()
        loop.run_until_complete(chan.send_message(test_string))
        ipfs_instance.pubsub.pub.assert_called_with('test_queue', test_string)

    def test_channel_queue_repr(self):
        ipfs_instance = MagicMock()
        chan = CallChannel('test_queue',
                           ipfs_instance)
        self.assertEqual('<CallChannel: queue_id=test_queue>', chan.__repr__())
