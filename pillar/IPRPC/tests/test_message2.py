from unittest import TestCase, SkipTest
from unittest.mock import MagicMock, patch
from ..channel import Channel
from ..messages import IPRPCMessage, IPRPCMessageType, PingRequestCall
import aioipfs
import asyncio


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


# "This is another example of how to do aio tests, but it is disabled"
#           "as it spams the logs"
@SkipTest
class TestChannelSendMessage2(TestCase):

    def setUp(self):
        ipfs_instance = aioipfs.AsyncIPFS()
        ipfs_instance.pubsub = AsyncMock()
        self.loop = asyncio.get_event_loop()
        self.channel = Channel('test', 'own_peer_id', ipfs_instance)
        self.test_message = IPRPCMessage(IPRPCMessageType.INLINE,
                                         src_peer='own_peer_id',
                                         dst_peer='other_peer_id',
                                         call=PingRequestCall())
        self.expected_data_result = \
            'eyJtc2dfdHlwZSI6IDEsICJicm9hZGNhc3QiOiBmYWx' \
            'zZSwgImNhbGwiOiB7Im1lc3NhZ2VfdHlwZSI6ICJQaW' \
            '5nUmVxdWVzdENhbGwifSwgInNyY19wZWVyIjogIm93b' \
            'l9wZWVyX2lkIiwgImRzdF9wZWVyIjogIm90aGVyX3Bl' \
            'ZXJfaWQifQ=='

    def tearDown(self):
        self.loop.run_until_complete(self.channel.ipfs.close())

    @patch('aioipfs.api.PubSubAPI.pub', new_callable=AsyncMock)
    def test_send_message_unexpected_result(self, *args):
        self.loop.run_until_complete(
            self.channel.send_message(self.test_message))
        self.assertRaises(AssertionError,
                          self.channel.ipfs.pubsub.pub.assert_called_with,
                          ('this is incorrect',))

    @patch('aioipfs.api.PubSubAPI.pub', new_callable=AsyncMock)
    def test_send_message_expected_result(self, *args):
        self.loop.run_until_complete(
            self.channel.send_message(self.test_message))
        self.channel.ipfs.pubsub.pub.assert_called_with(
            'test', self.expected_data_result)
