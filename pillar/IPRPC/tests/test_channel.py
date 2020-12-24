from unittest import TestCase
from ..channel import Channel
from unittest.mock import MagicMock


class TestChannel(TestCase):

    def test_channel_creation(self):
        ipfs_client = MagicMock()
        chan = Channel('test', ipfs_client)
        self.assertEqual('test', chan.queue_id)

    def test_encode_decode(self):
        test_string = "encodeAndDecodeMe!"
        ipfs_client = MagicMock()
        chan = Channel('test', ipfs_client)
        encoded_string = chan._encode_message(test_string)
        decoded_string = chan._decode_message(encoded_string)
        self.assertEqual(test_string, decoded_string)

    def test_except_on_invalid_message_deserialized(self):
        bad_serialized_message = '{"msg_type": 1, "broadcast": ' \
                                 'true, "call":' \
                                  ' {"message_type": "PingRPC", ' \
                                 '"ping_type": 1}' \
                                  ', "dst_peer": "<peer_id>"}'
        channel_instance = Channel('test', MagicMock())
        result = channel_instance._validate_message(
            bad_serialized_message
        )
        self.assertEqual(False, result)
