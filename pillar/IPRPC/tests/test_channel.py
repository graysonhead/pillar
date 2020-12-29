from unittest import TestCase, SkipTest
from ..channel import CallChannel, PeerChannel
from unittest.mock import MagicMock
import aioipfs
import asyncio
import asynctest
from multiprocessing import Pipe


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

    def test_send_messages_from_pipe_consumes_message(self):
        ipfs_instance = aioipfs.AsyncIPFS()
        ipfs_instance.pubsub = AsyncMock()
        chan = CallChannel('test_queue',
                           ipfs_instance)
        test_string = "This is a test message"
        tx, rx = Pipe()
        tx.send(test_string)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(chan.send_message_from_pipe(rx))
        ipfs_instance.pubsub.pub.assert_called_with('test_queue', test_string)

    # This test doesn't seem to work consistently, disabling until I can figure
    # out why
    @SkipTest
    def test_retrieve_message_to_pipe(self):
        ipfs_instance = aioipfs.AsyncIPFS()
        test_string = "This is a test message"
        ipfs_instance.pubsub.sub = asynctest.MagicMock()
        ipfs_instance.pubsub.sub.__aiter__.return_value = range(5)

        chan = CallChannel('test_queue',
                           ipfs_instance)

        tx, rx = Pipe()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(chan.retrieve_messages_to_pipe(tx))
        self.assertEqual(test_string, rx.recv())


class TestPeerChannel(TestCase):

    def test_peerchannel_creation(self):
        peer_id = 'peer_id'
        tx_queue_id = 'tx_queue_id'
        rx_queue_id = 'rx_queue_id'
        pc = PeerChannel(peer_id, rx_queue_id, tx_queue_id)
        self.assertEqual(peer_id, pc.peer_id)
        self.assertEqual(tx_queue_id, pc.tx_queue_id)
        self.assertEqual(rx_queue_id, pc.rx_queue_id)
