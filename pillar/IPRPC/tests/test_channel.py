from ..channel import IPRPCChannel, PeeringStatus
from ..messages import PeeringHello
import asynctest
import aioipfs
import logging
import time

logging.basicConfig(level=logging.INFO)


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

        async def return_id():
            return {"ID": "this_peers_id"}
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

# class OldTestIPRPCChannel(TestCase):
#
#     def setUp(self) -> None:
#
#         async def return_id():
#             return {"ID": "this_peers_id"}
#         ipfs_instance = AsyncMagicMock()
#         self.channel = IPRPCChannel('test_id',
#                                     'testing_queue',
#                                     ipfs_instance)
#         self.channel.ipfs.pubsub = AsyncMagicMock()
#         self.channel.ipfs.core = AsyncMagicMock()
#         self.channel.ipfs.id = return_id
#
#     def test_channel_creation(self):
#         self.assertEqual('testing_queue', self.channel.queue_id)
#
#     def test_send_message(self):
#         test_string = "Hello, sending test message!"
#         loop = asyncio.get_event_loop()
#         loop.run_until_complete(self.channel._send_ipfs(test_string))
#         self.channel.ipfs.pubsub.pub.assert_called_with('testing_queue',
#                                                         test_string)
#
#     def test_receive_message(self):
#
#         async def return_message_string(self):
#             list = [
#                 PeeringHello(initiator_id='test_peer')
#             ]
#             for i in list:
#                 data = i.serialize_to_json()
#                 yield {'from': 'fake_peer'.encode('utf-8'),
#                        'data': data.encode('utf-8')}
#         self.channel.ipfs.pubsub.sub = return_message_string
#
#         async def get_messages():
#             messages = []
#             async for message in self.channel._get_from_ipfs():
#                 messages.append(message)
#             return messages
#
#         loop = asyncio.get_event_loop()
#         messages = loop.run_until_complete(get_messages())
#         expected = ['{"message_type": "PeeringHello", '
#                     '"initiator_id": "test_peer"}']
#         self.assertEqual(expected, messages)
#
#     def test_recieve_call(self):
#         call = PeeringHello(initiator_id='test_peer')
#
#         async def return_message_string(self):
#             list = [
#                 call
#             ]
#             for i in list:
#                 data = i.serialize_to_json()
#                 yield {'from': 'fake_peer'.encode('utf-8'),
#                        'data': data.encode('utf-8')}
#
#         async def get_calls():
#             calls = []
#             async for message in self.channel._get_message():
#                 calls.append(message)
#             return calls
#
#         self.channel.ipfs.pubsub.sub = return_message_string
#         loop = asyncio.get_event_loop()
#         deserialized_results = loop.run_until_complete(get_calls())
#         expected_results = [call.serialize_to_json()]
#         serialized_results = list(map(lambda i: i.serialize_to_json(),
#                                   deserialized_results))
#         self.assertEqual(expected_results, serialized_results)
#
#     def test_log_recieve_bad_call(self):
#         async def return_message_string(self):
#             list = [
#                 '{"this": is, "bad"; "json}'
#             ]
#             for i in list:
#                 yield {'from': 'fake_peer'.encode('utf-8'),
#                        'data': i.encode('utf-8')}
#
#         async def get_calls():
#             calls = []
#             async for message in self.channel._get_message():
#                 calls.append(message)
#             return calls
#
#         self.channel.ipfs.pubsub.sub = return_message_string
#         loop = asyncio.get_event_loop()
#
#         with self.assertLogs(level='WARNING') as log:
#             loop.run_until_complete(get_calls())
#             self.assertEqual(1, len(log.records))
#
#     def test_channel_repr(self):
#         repr_string = self.channel.__repr__()
#         expected = '<IPRPCChannel:queue_id=testing_queue,peer_id=None,' \
#                    'status=IDLE>'
#         self.assertEqual(expected, repr_string)
#
#     def test_send_call(self):
#         test_call = PeeringHello(initiator_id="hi")
#         loop = asyncio.get_event_loop()
#         self.channel = AsyncMock()
#         loop.run_until_complete(self.channel._send_message(test_call))
#         self.channel._send_ipfs.assert_called_with(test_call.
#                                                    serialize_to_json())
#
#     def test_channel_own_peer_id_set(self):
#         self.channel.ipfs.core.id = AsyncMock(return_value={"ID": "test_id"})
#         loop = asyncio.get_event_loop()
#         loop.run_until_complete(self.channel._set_our_ipfs_peer_id())
#         self.assertEqual('test_id', self.channel.our_ipfs_peer_id)
