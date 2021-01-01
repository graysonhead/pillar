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

    def test_receive_message(self):

        async def return_message_string(self):
            list = [
                PeeringHello(initiator_id='test_peer')
            ]
            for i in list:
                data = i.serialize_to_json()
                yield {'from': 'fake_peer'.encode('utf-8'),
                       'data': data.encode('utf-8')}
        self.channel.ipfs.pubsub.sub = return_message_string

        async def get_messages():
            messages = []
            async for message in self.channel._get_from_ipfs():
                messages.append(message)
            return messages

        loop = asyncio.get_event_loop()
        messages = loop.run_until_complete(get_messages())
        expected = ['{"message_type": "PeeringHello", '
                    '"initiator_id": "test_peer"}']
        self.assertEqual(expected, messages)

    def test_recieve_call(self):
        call = PeeringHello(initiator_id='test_peer')

        async def return_message_string(self):
            list = [
                call
            ]
            for i in list:
                data = i.serialize_to_json()
                yield {'from': 'fake_peer'.encode('utf-8'),
                       'data': data.encode('utf-8')}

        async def get_calls():
            calls = []
            async for message in self.channel._get_message():
                calls.append(message)
            return calls

        self.channel.ipfs.pubsub.sub = return_message_string
        loop = asyncio.get_event_loop()
        deserialized_results = loop.run_until_complete(get_calls())
        expected_results = [call.serialize_to_json()]
        serialized_results = list(map(lambda i: i.serialize_to_json(),
                                  deserialized_results))
        self.assertEqual(expected_results, serialized_results)

    def test_log_recieve_bad_call(self):
        async def return_message_string(self):
            list = [
                '{"this": is, "bad"; "json}'
            ]
            for i in list:
                yield {'from': 'fake_peer'.encode('utf-8'),
                       'data': i.encode('utf-8')}

        async def get_calls():
            calls = []
            async for message in self.channel._get_message():
                calls.append(message)
            return calls

        self.channel.ipfs.pubsub.sub = return_message_string
        loop = asyncio.get_event_loop()

        with self.assertLogs(level='WARNING') as log:
            loop.run_until_complete(get_calls())
            self.assertEqual(1, len(log.records))

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
