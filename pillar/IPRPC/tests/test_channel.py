from unittest import TestCase
from ..channel import IPRPCChannel
from ..messages import PeeringHello
from unittest.mock import MagicMock
import aioipfs
import asyncio
import logging

logging.basicConfig(level=logging.INFO)


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


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
