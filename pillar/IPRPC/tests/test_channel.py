from ..channel import IPRPCChannel, PeeringStatus, generate_queue_id
from ..messages import PeeringHello, \
    PeeringHelloResponse, \
    IPRPCMessage, \
    PeeringKeepalive
from ...ipfs import IPFSClient
from multiprocessing import Queue
from multiprocessing.connection import Connection
from unittest import SkipTest
from queue import Empty
from datetime import datetime, timedelta
import asynctest
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


class TestMessage(IPRPCMessage):
    attributes = {}


return_id = {"ID": "test_id"}


class TestRXChannelSubProcess(asynctest.TestCase):

    @asynctest.patch('pillar.ipfs.IPFSClient.get_id',
                     new=asynctest.CoroutineMock(return_value=return_id))
    @asynctest.patch('pillar.ipfs.IPFSClient')
    def setUp(self, mock) -> None:
        self.channel = IPRPCChannel('test_id',
                                    'testing_queue',
                                    pre_shared_key='test_preshared_key')

    def test_recieve_message_from_thread(self):
        message = TestMessage()
        mock_queue = Queue()

        async def mock_get_message(*args):
            yield mock_queue.get()

        self.channel._get_message = mock_get_message
        rx_output = self.channel.rx_output
        self.channel.start()
        mock_queue.put(message)
        recieved_message = rx_output.recv()
        self.assertEqual(message.serialize_to_json(),
                         recieved_message.serialize_to_json())
        self.channel.terminate()

    @SkipTest
    def test_send_message_to_thread(self):
        message = TestMessage()
        mock_queue = Queue()

        async def send_message(message: IPRPCMessage):
            mock_queue.put(message)

        self.channel._send_message = send_message
        self.channel.status = PeeringStatus.ESTABLISHED
        tx_input = self.channel.tx_input
        self.channel.start()
        tx_input.send(message)
        test_message = mock_queue.get()
        self.assertEqual(message.serialize_to_json(),
                         test_message.serialize_to_json())
        self.channel.terminate()

    @SkipTest
    def test_dont_send_test_message_if_not_established(self):
        message = TestMessage()
        mock_queue = Queue()

        async def send_message(message: IPRPCMessage):
            mock_queue.put(message)

        self.channel._send_message = send_message
        tx_input = self.channel.tx_input
        self.channel.ipfs = asynctest.MagicMock()
        self.channel.start()
        tx_input.send(message)
        mock_queue.get()  # Hit the queue once to clear the PeeringHello
        with self.assertRaises(Empty):
            mock_queue.get(timeout=1)
        self.channel.terminate()


class TestIPRPCChannel(asynctest.TestCase):

    async def setUp(self) -> None:
        ipfs_instance = IPFSClient()
        ipfs_instance.get_id = asynctest.CoroutineMock(
            return_value={
                "ID": "test_id"
            })
        ipfs_instance.pubsub = asynctest.MagicMock()
        self.channel = IPRPCChannel('test_id',
                                    'testing_queue',
                                    ipfs_instance=ipfs_instance)

    @asynctest.patch('pillar.ipfs.IPFSClient.send_pubsub_message')
    async def test_send_text(self, mocked_func):
        test_string = "Hello, sending test message!"
        await self.channel._send_ipfs(test_string)
        mocked_func.assert_awaited_with(
            generate_queue_id(
                self.channel.id,
                self.channel.peer_id),
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

    @SkipTest
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

        self.channel.ipfs.get_pubsub_message = return_message_string
        messages = await get_raw_messages()
        self.assertEqual([test_text], messages)

    async def test_get_message(self):
        test_message = PeeringHello(initiator_id='peer_test')

        async def return_string_generator(*args):
            list = [test_message.serialize_to_json()]
            for i in list:
                yield i

        async def get_messages():
            messages = []
            async for message in self.channel._get_message('testqueue'):
                messages.append(message)
            return messages
        self.channel._get_from_ipfs = return_string_generator
        messages = await get_messages()
        self.assertEqual([test_message.serialize_to_json()],
                         list(map(lambda i: i.serialize_to_json(), messages)))

    async def test_message_deserialize_failure(self):
        test_string = "This isn't real json tbh"

        async def return_string_generator(*args):
            list = [test_string]
            for i in list:
                yield i

        async def get_messages(*args):
            messages = []
            async for message in self.channel._get_message('testqueue'):
                messages.append(message)
            return messages

        self.channel._get_from_ipfs = return_string_generator
        with self.assertLogs(level='WARNING') as log:
            await get_messages()
            self.assertEqual(1, len(log.records))

    def test_channel_repr(self):
        repr_string = self.channel.__repr__()
        expected = '<IPRPCChannel:peer_id=testing_queue>'
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

    def test_returns_pipe_endpoints(self):
        tx, rx = self.channel.get_pipe_endpoints()
        self.assertEqual(Connection, type(tx))
        self.assertEqual(Connection, type(rx))

    async def test_handle_tx_queue_messages(self):
        test_message = TestMessage()
        self.channel.status = PeeringStatus.ESTABLISHED
        self.channel._send_message = asynctest.CoroutineMock()
        tx, rx = self.channel.get_pipe_endpoints()
        tx.send(test_message)
        await self.channel._handle_tx_queue_messages()
        self.channel._send_message.assert_awaited()

    async def test_respond_to_peeringhello(self):
        test_peering_hello = PeeringHello(initiator_id='other_peer')
        mock_queue = Queue()

        async def send_message(message: IPRPCMessage):
            mock_queue.put(message)

        async def yield_peering_hello(*args):
            yield test_peering_hello

        self.channel._get_message = yield_peering_hello
        self.channel._send_message = send_message
        await self.channel._handle_incoming_messages('testqueue')
        response = mock_queue.get()
        self.assertEqual(PeeringHelloResponse, type(response))

    async def test_recieve_peeringhello_response(self):
        peering_hello_response = PeeringHelloResponse(
            responder_id='other_peer'
        )

        async def yield_peering_hello_response(*args):
            yield peering_hello_response

        self.channel._get_message = yield_peering_hello_response
        await self.channel._handle_incoming_messages('testqueue')
        self.assertEqual(PeeringStatus.ESTABLISHED, self.channel.status)
        self.assertEqual('other_peer', self.channel.peer_id)

    async def test_receive_keepalive_sets_timeout(self):
        keepalive = PeeringKeepalive()

        async def yield_peering_keepalive(*args):
            yield keepalive

        self.channel._get_message = yield_peering_keepalive
        await self.channel._handle_incoming_messages('testqueue')
        self.assertNotEqual(None, self.channel.timeout)

    async def test_sends_message_to_pipe(self):
        test_message = TestMessage()

        async def yield_test_message(*args):
            yield test_message

        self.channel._get_message = yield_test_message
        await self.channel._handle_incoming_messages('testqueue')
        tx, rx = self.channel.get_pipe_endpoints()
        message = rx.recv()
        self.assertEqual(test_message.serialize_to_json(),
                         message.serialize_to_json()
                         )

    @asynctest.patch(
        'pillar.IPRPC.channel.IPRPCChannel._handle_incoming_messages')
    async def test_handle_message_current_window(self, func):
        self.channel._establish_and_rotate_queues()
        await self.channel._handle_messages_current_window()
        func.assert_awaited_with(self.channel.queues[1])

    @asynctest.patch(
        'pillar.IPRPC.channel.IPRPCChannel._handle_incoming_messages')
    async def test_handle_message_previous_window(self, func):
        await self.channel._handle_messages_previous_window()
        queue_id = generate_queue_id(
            self.channel.id,
            self.channel.peer_id,
            datetime=datetime.utcnow() - timedelta(hours=1)
        )
        func.assert_awaited_with(queue_id)

    @asynctest.patch(
        'pillar.IPRPC.channel.IPRPCChannel._handle_incoming_messages')
    async def test_handle_message_next_window(self, func):
        await self.channel._handle_messages_next_window()
        test_time = datetime.utcnow() + timedelta(hours=1)
        queue_id = generate_queue_id(
            self.channel.id,
            self.channel.peer_id,
            datetime=test_time
        )
        func.assert_awaited_with(queue_id)

    @asynctest.patch(
        'pillar.IPRPC.channel.IPRPCChannel._establish_and_rotate_queues'
    )
    async def test_async_queue_rotation_wrapper(self, func):
        await self.channel._async_rotate_queues_wrapper()
        func.assert_called()

    async def test_sliding_queue_rotation(self):
        self.channel.queues = ['old_values']
        self.channel._establish_and_rotate_queues()
        self.assertNotEqual(['old_values'], self.channel.queues)
        self.assertEqual(3, self.channel.queues.__len__())


class TestQueueIDGenerator(asynctest.TestCase):

    def test_queue_id_different_order(self):
        fingerprint_1 = '6A2F 421B D348 3324 C381  40DA 073B C320 0DEC 1B82'
        fingerprint_2 = '8B1E 9C88 2414 2D5B D80C  C383 1E0B D385 940E 0713'

        channel_id_1 = generate_queue_id(fingerprint_1, fingerprint_2)
        channel_id_2 = generate_queue_id(fingerprint_2, fingerprint_1)
        self.assertEqual(channel_id_1, channel_id_2)
