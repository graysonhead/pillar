from unittest import TestCase
from ..IPRPC import IPRPCCall, \
    IPRPCRegistry, \
    PingRPC, \
    PingType, \
    IPRPCMessage, \
    IPRPCMessageType
from ..exceptions import IPRPCException


class TestIPRPCRegistry(TestCase):

    def test_class_registration(self):

        @IPRPCRegistry.register_rpc_call
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}

        result = IPRPCRegistry.message_types.get("TestRPCCall")
        self.assertEqual(TestRPCCall, result)

    def test_iprpcregistry_json_deserialization(self):
        @IPRPCRegistry.register_rpc_call
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        serialized_string = """{"message_type": "TestRPCCall", "test": "Hello"}"""
        message = IPRPCRegistry.deserialize_from_json(serialized_string)
        self.assertEqual(TestRPCCall, type(message))
        self.assertEqual("Hello", message.test)


class TestIPRPCCall(TestCase):

    def test_message_type_attr(self):
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        test_instance = TestRPCCall(test="Hello")
        self.assertEqual("TestRPCCall", test_instance.message_type)

    def test_attribute_assignment(self):
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        test_instance = TestRPCCall(test="Hello")
        self.assertEqual("Hello", test_instance.test)

    def test_catch_invalid_type(self):
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        with self.assertRaises(IPRPCException):
            test_instance = TestRPCCall(test=1)

    def test_catch_invalid_arg(self):
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        with self.assertRaises(IPRPCException):
            test_instance = TestRPCCall(test="Hello", fakearg=True)

    def test_catch_missing_arg(self):
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        with self.assertRaises(IPRPCException):
            test_instance = TestRPCCall()

    def test_rpc_json_serialization(self):
        class TestRPCCall(IPRPCCall):
            attributes = {"test": str}
        test_message = TestRPCCall(test="Hello")
        result = test_message.serialize_to_json()
        expected = """{"message_type": "TestRPCCall", "test": "Hello"}"""
        self.assertEqual(expected, result)


class TestPingRPCCall(TestCase):

    def test_create_ping_call(self):
        ping_instance = PingRPC(ping_type=PingType.REQUEST)
        self.assertEqual(PingRPC, type(ping_instance))


class TestIPRPCMessage(TestCase):

    def test_iprpc_message_inline_broadcast(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        message = IPRPCMessage(
            IPRPCMessageType.INLINE,
            broadcast=True,
            call=call_instance,
        )
        self.assertEqual(1, message.msg_type)
        self.assertEqual(True, message.broadcast)
        self.assertEqual(call_instance, message.call)

    def test_iprpc_message_cid_broadcast(self):
        message = IPRPCMessage(
            IPRPCMessageType.CID,
            broadcast=True,
            msg_cid="<msg_cid>"
        )
        self.assertEqual(IPRPCMessageType.CID, message.msg_type)
        self.assertEqual(True, message.broadcast)

    def test_iprpc_message_inline_unencrypted_serialize(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        message = IPRPCMessage(
            IPRPCMessageType.INLINE,
            call=call_instance,
            dst_peer="<peer_id>",
        )
        raw_message = message.serialize_to_json()
        expected_result = '{"msg_type": 1, "broadcast": false, "call": {"message_type": "PingRPC", "ping_type": 1}, "dst_peer": "<peer_id>"}'
        self.assertEqual(expected_result, raw_message)

    def test_iprpc_message_inline_encrypted_deserialize(self):
        json_string = '{"msg_type": 1, "broadcast": false, "call": {"message_type": "PingRPC", "ping_type": 1}, "dst_peer": "<peer_id>"}'
        message = IPRPCMessage.deserialize_from_json(json_string)
        self.assertEqual(IPRPCMessageType.INLINE, message.msg_type)
        self.assertEqual(False, message.broadcast)
        self.assertEqual(PingRPC, type(message.call))
        self.assertEqual(IPRPCMessage, type(message))


class TestIPRPCMessageValidation(TestCase):

    def test_iprpc_message_invalid_broadcast_and_dst_peer(self):
        with self.assertRaises(IPRPCException):
            call_instance = PingRPC(ping_type=PingType.REQUEST)
            message = IPRPCMessage(
                IPRPCMessageType.INLINE,
                dst_peer="<peer_id>",
                broadcast=True,
                call=call_instance
            )

    def test_iprpc_message_invalid_inline_with_cid(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        with self.assertRaises(IPRPCException):
            message = IPRPCMessage(
                IPRPCMessageType.INLINE,
                dst_peer="<peer_id>",
                call=call_instance,
                msg_cid="<cid_id>"
            )

    def test_iprpc_message_invalid_cid_with_inline(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        with self.assertRaises(IPRPCException):
            message = IPRPCMessage(
                IPRPCMessageType.CID,
                dst_peer="<peer_id>",
                call=call_instance,
                msg_cid="<cid_id>"
            )

    def test_iprpc_message_invalid_cid_missing_arg(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        with self.assertRaises(IPRPCException):
            message = IPRPCMessage(
                IPRPCMessageType.CID,
                dst_peer="<peer_id>",
            )

    def test_iprpc_message_invalid_inline_missing_arg(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        with self.assertRaises(IPRPCException):
            message = IPRPCMessage(
                IPRPCMessageType.INLINE,
                dst_peer="<peer_id>",
            )

    def test_iprpc_message_invalid_broadcast_with_peer(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        with self.assertRaises(IPRPCException):
            message = IPRPCMessage(
                IPRPCMessageType.CID,
                dst_peer="<peer_id>",
                broadcast=True,
                msg_cid="<cid_id>"
            )

    def test_iprpc_message_invalid_broadcast_false_without_peer(self):
        call_instance = PingRPC(ping_type=PingType.REQUEST)
        with self.assertRaises(IPRPCException):
            message = IPRPCMessage(
                IPRPCMessageType.CID,
                broadcast=False,
                msg_cid="<cid_id>"
            )