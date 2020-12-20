from unittest import TestCase
from ..IPRPC import IPRPCCall, IPRPCRegistry, PingRPC, PingType
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