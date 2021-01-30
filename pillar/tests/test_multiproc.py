"""
IMPORTANT: This file is referenced via line numbers in the documentation on the
"Development Guide > Threading Model" page. If you modify this file, please
ensure that the examples on this page are still captured correctly as their
line numbers will have changed!
"""
import asynctest
import time
from uuid import uuid4
from ..multiproc import PillarThreadMethodsRegister, \
    PillarWorkerThread, \
    PillarThreadMixIn, \
    QueueCommand


class TestClassRegister(PillarThreadMethodsRegister):
    """
    This subclass stores a list of callable methods on the Worker (added via
    the below decorator) that allow them to be called on the interface
    attribute.
    """
    pass


class TestClass(PillarWorkerThread):
    """
    This is the class that will spawn one or more worker threads where
    commands will actually be run when interface methods are called.

    The method register class must be specified as a class attribute as below.
    """
    methods_register_class = TestClassRegister

    @TestClassRegister.register_method
    def return_hi(self):
        """
        The above decorator allows the interface added by TestClassMixIn to
        trigger this method from a remote process and retrieve it's output.
        """
        return "hi"

    @TestClassRegister.register_method
    async def return_hi_async(self):
        """
        Async methods work as well
        """
        return "hi"


class TestClassMixIn(PillarThreadMixIn):
    """
    This class is inherited by the class that interacts with TestClass.

    The queue_thread_class attribute must contain the target worker thread
    class so the queues and methods of the interface can be set up correctly.

    Additionally, the interface_name must be specified, and will determine
    the attribute name of the interface on the parent class.
    """
    queue_thread_class = TestClass
    interface_name = "test_interface"


class TestMultiProc(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_class_instance = TestClass()
        self.test_class_instance.shutdown_callback.set()

    def test_class_method_registered(self):
        self.assertIn('return_hi', TestClassRegister.methods.keys())

    async def test_class_remote_command_execute(self):
        command = QueueCommand('return_hi')
        self.test_class_instance.command_queue.put(command)
        time.sleep(.01)
        await self.test_class_instance.run_queue_commands()
        time.sleep(.01)
        result = self.test_class_instance.output_queue.get_nowait()
        self.assertEqual('hi', result[command.id])

    async def test_class_remote_command_execute_async(self):
        command = QueueCommand('return_hi_async')
        self.test_class_instance.command_queue.put(command)
        time.sleep(.01)
        await self.test_class_instance.run_queue_commands()
        time.sleep(.01)
        result = self.test_class_instance.output_queue.get_nowait()
        self.assertEqual('hi', result[command.id])


def echo_command_output(uuid):
    return {uuid: "somevalue"}


class TestPillarQueueInterface(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_class_instance = TestClass()
        self.interface = TestClassMixIn()

    def test_class_remote_command_execute_autogen_method(self):
        self.interface.test_interface.\
            get_command_output = echo_command_output
        return_value = self.interface.test_interface.\
            return_hi()
        self.assertIn('somevalue', return_value.values())

    def test_get_return_value_from_queue(self):
        test_uuid = uuid4()
        self.test_class_instance.output_queue.put(
            {test_uuid: "test_value"}
        )
        return_value = self.interface.test_interface.\
            get_command_output(test_uuid)
        self.assertEqual("test_value", return_value)

    def test_returns_wrong_uuid_to_queue(self):
        test_uuid = uuid4()
        wrong_uuid = uuid4()
        test_output = {wrong_uuid: "test_value"}
        self.test_class_instance.output_queue.put(test_output)
        time.sleep(.01)
        self.interface.test_interface. \
            get_command_output(test_uuid, only_once=True)
        time.sleep(.01)
        output = self.test_class_instance.output_queue.get_nowait()
        self.assertEqual(test_output, output)
