from unittest import TestCase
from ..channel import Channel
from ..messages import IPRPCMessage, PingRequestCall, IPRPCMessageType
from unittest.mock import MagicMock
from binascii import Error as BinASCIIError
import aioipfs
import asyncio
import logging

logging.basicConfig(level=logging.ERROR)


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


class TestChannel(TestCase):

    def test_channel_creation(self):
        ipfs_client = MagicMock()
        chan = Channel('test', 'own_peer_id', ipfs_client)
        self.assertEqual('test', chan.queue_id)

    def test_encode_decode(self):
        test_string = "encodeAndDecodeMe!"
        ipfs_client = MagicMock()
        chan = Channel('test', 'own_peer_id', ipfs_client)
        encoded_string = chan._encode_message(test_string)
        decoded_string = chan._decode_message(encoded_string)
        self.assertEqual(test_string, decoded_string)

    def test_except_on_invalid_message_deserialized(self):
        bad_serialized_message = '{"msg_type": 1, "broadcast": ' \
                                 'true, "call":' \
            ' {"message_type": "PingRequestCall", ' \
                                 '"ping_type": 1}' \
            ', "dst_peer": "<peer_id>"}'
        channel_instance = Channel('test', 'own_peer_id', MagicMock())
        result = channel_instance._validate_message(
            bad_serialized_message
        )
        self.assertEqual(False, result)

    def test_invalid_base64_encoding(self):
        bad_base64 = b'b%27eyJtc2dfdHlwZSI6IDEsICJicm9hZGNhc3QiOiB0cnVlLCA' \
                     b'iY2FsbCI6IHsibWVzc2FnZV90eXBlIjogIlBpbmdSUEMiLCAicGl' \
                     b'uZ190eXBlIjogMX19%27'
        channel_instance = Channel('test', 'own_peer_id', MagicMock())
        with self.assertRaises(BinASCIIError):
            channel_instance._decode_message(bad_base64)


class TestChannelSendMessage(TestCase):

    def test_send_message(self):
        ipfs_instance = aioipfs.AsyncIPFS()
        ipfs_instance.pubsub = AsyncMock()
        channel = Channel('test', 'own_peer_id', ipfs_instance)
        test_message = IPRPCMessage(IPRPCMessageType.INLINE,
                                    src_peer='own_peer_id',
                                    dst_peer='other_peer_id',
                                    call=PingRequestCall())
        loop = asyncio.get_event_loop()
        loop.run_until_complete(channel.send_message(test_message))
        expected_data_result = 'eyJtc2dfdHlwZSI6IDEsICJicm9hZGNhc3QiOiBmYWx' \
                               'zZSwgImNhbGwiOiB7Im1lc3NhZ2VfdHlwZSI6ICJQaW' \
                               '5nUmVxdWVzdENhbGwifSwgInNyY19wZWVyIjogIm93b' \
                               'l9wZWVyX2lkIiwgImRzdF9wZWVyIjogIm90aGVyX3Bl' \
                               'ZXJfaWQifQ=='
        ipfs_instance.pubsub.pub.assert_called_with('test',
                                                    expected_data_result)
        loop.run_until_complete(ipfs_instance.close())
