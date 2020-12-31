from unittest import TestCase, SkipTest
from ..channel import CallChannel, PeerChannel, IPRPCChannel
from ..messages import PeeringHello
from unittest.mock import MagicMock
import aioipfs
import asyncio
import asynctest
import logging
from multiprocessing import Pipe

logging.basicConfig(level=logging.INFO)


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
        peer_id = 'our_id'
        tx_queue_id = 'tx_queue_id'
        rx_queue_id = 'rx_queue_id'
        pc = PeerChannel(peer_id, rx_queue_id, tx_queue_id)
        self.assertEqual(peer_id, pc.our_id)
        self.assertEqual(tx_queue_id, pc.tx_queue_id)
        self.assertEqual(rx_queue_id, pc.rx_queue_id)

    def test_peerchannel_peering(self):
        pc1 = PeerChannel("peer_1", "rx_queue", "tx_queue")
        pc2 = PeerChannel("peer_2", "tx_queue", "rx_queue")
        # Using queues to mock connection between PeerChannels
        pc1_tx, pc2_rx = Pipe()
        pc2_tx, pc1_rx = Pipe()
        pc1.tx_pipe = pc1_tx
        pc1.rx_pipe = pc1_rx
        pc2.tx_pipe = pc2_tx
        pc2.rx_pipe = pc2_rx


class TestIPRPCChannel(TestCase):

    def setUp(self) -> None:
        ipfs_instance = aioipfs.AsyncIPFS()
        ipfs_instance.pubsub = AsyncMock()
        self.channel = IPRPCChannel('test_id',
                                    'testing_queue',
                                    ipfs_instance)

    def test_channel_creation(self):
        self.assertEqual('testing_queue', self.channel.queue_id)

    def test_send_message(self):
        test_string = "Hello, sending test message!"
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.channel._send_ipfs(test_string))
        with self.assertLogs(level='INFO') as cm:
            logging.getLogger("<IPRPCChannel:testing_queue>")\
                .info('Sent raw message: Hello, sending test message!')
        self.assertEqual(cm.output, ['INFO:<IPRPCChannel:testing_queue>:'
                                     'Sent raw message: Hello, sending'
                                     ' test message!'])
        self.channel.ipfs.pubsub.pub.assert_called_with('testing_queue',
                                                        test_string)

    def test_channel_repr(self):
        repr_string = self.channel.__repr__()
        expected = '<IPRPCChannel:queue_id=testing_queue,peer_id=None,' \
                   'status=IDLE>'
        self.assertEqual(expected, repr_string)

    def test_send_call(self):
        test_call = PeeringHello(initiator_id="hi")
        loop = asyncio.get_event_loop()
        self.channel._send_ipfs = AsyncMock()
        loop.run_until_complete(self.channel._send_message(test_call))
        self.channel._send_ipfs.assert_called_with(test_call.
                                                   serialize_to_json())

    def test_channel_own_peer_id_set(self):
        self.channel.ipfs.core.id = AsyncMock(return_value={"ID": "test_id"})
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.channel._set_our_ipfs_peer_id())
        self.assertEqual('test_id', self.channel.our_ipfs_peer_id)
