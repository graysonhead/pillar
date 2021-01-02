from ..channel import IPRPCChannel, PeeringStatus
from ..messages import PeeringHello
import asynctest
import aioipfs
import time


def generate_fake_pubsub_message(src_peer: str,
                                 data: str,
                                 topicIDs: list):
    return {
        'from': src_peer.encode('utf-8'),
        'data': data.encode('utf-8'),
        'topicIDs': topicIDs,
        'seqno': "\x16V4t'\x03\x13\xdc".encode('utf-8')
    }


class TestIPRPCChannel(asynctest.TestCase):

    def setUp(self) -> None:
        ipfs_instance = aioipfs.AsyncIPFS()
        ipfs_instance.core.id = asynctest.CoroutineMock(return_value={
            "ID": "test_id"
        })
        self.channel = IPRPCChannel('test_id',
                                    'testing_queue',
                                    ipfs_instance)

    async def test_send_text(self):
        test_string = "Hello, sending test message!"
        self.channel.ipfs.pubsub.pub = asynctest.CoroutineMock(
            return_value=[test_string])
        await self.channel._send_ipfs(test_string)
        self.channel.ipfs.pubsub.pub.assert_awaited_with('testing_queue',
                                                         test_string)

    async def test_send_message(self):
        test_class = PeeringHello(initiator_id=self.channel.id)
        self.channel._send_ipfs = asynctest.CoroutineMock()
        await self.channel._send_message(test_class)
        self.channel._send_ipfs.assert_awaited_with(
            test_class.serialize_to_json()
        )

    async def test_channel_own_peer_id_set(self):
        await self.channel._set_our_ipfs_peer_id()
        self.assertEqual('test_id', self.channel.our_ipfs_peer_id)

    async def test_get_text(self):
        test_text = "Hello, receiving this message!"
        raw_message = generate_fake_pubsub_message('other_peer',
                                                   test_text,
                                                   ['testing_queue'])

        async def return_message_string(self):
            list = [raw_message]
            for i in list:
                yield i

        async def get_raw_messages():
            messages = []
            async for message in self.channel._get_from_ipfs():
                messages.append(message)
            return messages

        self.channel.ipfs.pubsub.sub = return_message_string
        messages = await get_raw_messages()
        self.assertEqual([test_text], messages)

    async def test_get_message(self):
        test_message = PeeringHello(initiator_id='peer_test')

        async def return_string_generator():
            list = [test_message.serialize_to_json()]
            for i in list:
                yield i

        async def get_messages():
            messages = []
            async for message in self.channel._get_message():
                messages.append(message)
            return messages
        self.channel._get_from_ipfs = return_string_generator
        messages = await get_messages()
        self.assertEqual([test_message.serialize_to_json()],
                         list(map(lambda i: i.serialize_to_json(), messages)))

    async def test_message_deserialize_failure(self):
        test_string = "This isn't real json tbh"

        async def return_string_generator():
            list = [test_string]
            for i in list:
                yield i

        async def get_messages():
            messages = []
            async for message in self.channel._get_message():
                messages.append(message)
            return messages

        self.channel._get_from_ipfs = return_string_generator
        with self.assertLogs(level='WARNING') as log:
            await get_messages()
            self.assertEqual(1, len(log.records))

    def test_channel_repr(self):
        repr_string = self.channel.__repr__()
        expected = '<IPRPCChannel:queue_id=testing_queue,peer_id=None,' \
                   'status=IDLE>'
        self.assertEqual(expected, repr_string)

    def test_peering_status_change(self):
        self.channel._change_peering_status(PeeringStatus.ESTABLISHING)
        self.assertEqual(PeeringStatus.ESTABLISHING, self.channel.status)

    async def test_handle_establish_connection(self):
        self.channel._send_message = asynctest.CoroutineMock()
        await self.channel._handle_establish_connection()
        self.channel._send_message.assert_awaited()

    async def test_handle_timeout(self):
        self.channel.timeout = time.time() - 5
        self.channel.status = PeeringStatus.ESTABLISHED
        await self.channel._handle_timeout()
        self.assertEqual(PeeringStatus.IDLE, self.channel.status)

    async def test_handle_keepalive(self):
        self.channel._send_message = asynctest.CoroutineMock()
        self.channel.keepalive_send_timeout = time.time() - 5
        self.channel.status = PeeringStatus.ESTABLISHED
        await self.channel._handle_keepalive()
        self.channel._send_message.assert_awaited()
