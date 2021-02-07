import pillar
import asynctest
from ..ipfs import IPFSClient, IPFSWorker
from unittest.mock import AsyncMock
from unittest import skip


async def test_message_return(*args, **kwargs):
    yield 'test'


class TestIPFSClient(asynctest.TestCase):

    def setUp(self) -> None:
        self.instance = IPFSClient()

    @asynctest.patch("aioipfs.api.PubSubAPI.pub")
    async def test_send_pubsub_message(self, mock_pub):
        test_string = "Hello, sending test message!"
        await self.instance.send_pubsub_message('queue', test_string)
        mock_pub.assert_awaited_with('queue', test_string)

    @asynctest.patch('pillar.ipfs.aioipfs.api.PubSubAPI.sub',
                     new=test_message_return)
    async def test_recieve_pubsub_message(self):
        messages = []
        async for message in self.instance.get_pubsub_message('queue'):
            messages.append(message)
        self.assertEqual(['test'], messages)

    @asynctest.patch('aioipfs.api.CoreAPI.id')
    async def test_get_id(self, mock_func):
        await self.instance.get_id()
        mock_func.assert_awaited()

    @asynctest.patch('aioipfs.api.CoreAPI.get')
    async def test_get_file(self, mock_func):
        await self.instance.get_file('A file', dstdir='/tmp/fakefile')
        mock_func.assert_awaited_with('A file', '/tmp/fakefile')

    @asynctest.patch('pillar.ipfs.aioipfs.api.CoreAPI.add',
                     new=AsyncMock())
    async def test_add_file(self):
        ret = await self.instance.add_file('/tmp/file_path',
                                           recursive=True,
                                           return_client=True)
        ret.add.assert_awaited_with('/tmp/file_path',
                                    recursive=True)

    @skip
    @asynctest.patch('pillar.ipfs.aioipfs.api.CoreAPI.add_str')
    async def test_add_str(self, *args):
        await self.instance.add_str('test_string')
        pillar.ipfs.aioipfs.api.CoreAPI.add_str.add_str.assert_called_with(
            'test_string')


class TestIPFSWorker(asynctest.TestCase):

    def setUp(self) -> None:
        self.ipfs_client = AsyncMock()
        self.worker = IPFSWorker(ipfs_client=self.ipfs_client)

    async def test_get_file(self):
        await self.worker.get_file('fake_cid', dstdir='/test_dir')
        self.ipfs_client.get_file.assert_awaited_with('fake_cid',
                                                      dstdir='/test_dir')

    async def test_add_str(self):
        await self.worker.add_str('test_str')
        self.ipfs_client.add_str.assert_awaited_with('test_str')

    async def test_add_file(self):
        await self.worker.add_file('test_file')
        self.ipfs_client.add_file.assert_awaited_with('test_file')

    async def test_worker_repr(self):
        repr = str(self.worker)
        self.assertEqual("<IPFSWorker>", repr)
