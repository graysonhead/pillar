import asynctest
from ..ipfs import IPFSClient
from unittest import SkipTest


class TestIPFSClient(asynctest.TestCase):

    def setUp(self) -> None:
        self.instance = IPFSClient()

    @asynctest.patch("aioipfs.api.PubSubAPI.pub")
    async def test_send_pubsub_message(self, mock_pub):
        test_string = "Hello, sending test message!"
        await self.instance.send_pubsub_message('queue', test_string)
        mock_pub.assert_awaited_with('queue', test_string)

    # This needs to be mocked better
    @SkipTest
    @asynctest.patch('aioipfs.api.PubSubAPI.sub', new=asynctest.MagicMock())
    async def test_recieve_pubsub_message(self):
        self.instance.get_pubsub_message.__aiter__ = asynctest.MagicMock()
        async for message in self.instance.get_pubsub_message('queue'):
            pass
        self.instance.client.pubsub.sub.assert_awaited()

    @asynctest.patch('aioipfs.api.CoreAPI.id')
    async def test_get_id(self, mock_func):
        await self.instance.get_id()
        mock_func.assert_awaited()
