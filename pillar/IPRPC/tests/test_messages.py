from unittest import TestCase
from ..messages import IPRPCMessage, \
    IPRPCRegistry, \
    PingRequestCall, \
    InvitationMessage,\
    RegistrationRequestMessage
from pillar.exceptions import IPRPCMessageException


class TestIPRPCRegistry(TestCase):

    def test_class_registration(self):

        @IPRPCRegistry.register_rpc_call
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}

        result = IPRPCRegistry.message_types.get("TestRPCMessage")
        self.assertEqual(TestRPCMessage, result)

    def test_iprpcregistry_json_deserialization(self):
        @IPRPCRegistry.register_rpc_call
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        serialized_string = '{"message_type": '\
            '"TestRPCMessage", "test": "Hello"}'
        message = IPRPCRegistry.deserialize_from_json(serialized_string)
        self.assertEqual(TestRPCMessage, type(message))
        self.assertEqual("Hello", message.test)


class TestIPRPCCall(TestCase):

    def test_message_type_attr(self):
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        test_instance = TestRPCMessage(test="Hello")
        self.assertEqual("TestRPCMessage", test_instance.message_type)

    def test_attribute_assignment(self):
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        test_instance = TestRPCMessage(test="Hello")
        self.assertEqual("Hello", test_instance.test)

    def test_catch_invalid_type(self):
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        with self.assertRaises(IPRPCMessageException):
            TestRPCMessage(test=1)

    def test_catch_invalid_arg(self):
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        with self.assertRaises(IPRPCMessageException):
            TestRPCMessage(test="Hello", fakearg=True)

    def test_catch_missing_arg(self):
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        with self.assertRaises(IPRPCMessageException):
            TestRPCMessage()

    def test_rpc_json_serialization(self):
        class TestRPCMessage(IPRPCMessage):
            attributes = {"test": str}
        test_message = TestRPCMessage(test="Hello")
        result = test_message.serialize_to_json()
        expected = """{"message_type": "TestRPCMessage", "test": "Hello"}"""
        self.assertEqual(expected, result)


class TestPingRequestCall(TestCase):

    def test_create_ping_call(self):
        ping_instance = PingRequestCall()
        self.assertEqual(PingRequestCall, type(ping_instance))


class TestRegistrationRequestMessage(TestCase):
    maxDiff = 1000

    def setUp(self):
        self.serial_data = (
            '{\"message_type\": \"RegistrationRequestMessage\", '
            '\"invitation\": \"{\\"message_type\\": '
            '\\"InvitationMessage\\", \\"public_key_cid\\": '
            '\\"bogus\\", \\"preshared_key\\": \\"bogus\\", '
            '\\"channels_per_peer\\": 1, '
            '\\"channel_rotation_period\\": 1}\"}'
        )
        inv = InvitationMessage(
            public_key_cid='bogus',
            preshared_key='bogus',
            channels_per_peer=1,
            channel_rotation_period=1
        )

        self.rrm = RegistrationRequestMessage(invitation=inv)

    def test_serialize_registration_request_message(self):
        output = self.rrm.serialize_to_json()
        self.assertEqual(output, self.serial_data)

    def test_deserialize_registration_request_message(self):
        inst = IPRPCRegistry.deserialize_from_json(self.serial_data)
        self.assertEqual(type(inst), RegistrationRequestMessage)
