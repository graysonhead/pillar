"""
IMPORTANT: This file is referenced via line numbers in the documentation on the
"Development Guide > Threading Model" page. If you modify this file, please
ensure that the examples on this page are still captured correctly as their
line numbers will have changed!
"""
import asynctest
from ..multiproc import PillarThreadMethodsRegister, \
    PillarWorkerThread, \
    PillarThreadMixIn, \
    QueueCommand
from unittest import SkipTest


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
        self.test_class_interface_instance = TestClassMixIn()
        self.test_class_instance.start()

    def tearDown(self) -> None:
        self.test_class_instance.exit()

    def test_class_method_registered(self):
        self.assertIn('return_hi', TestClassRegister.methods.keys())

    def test_class_remote_command_execute(self):
        result = self.test_class_interface_instance.\
            test_interface.command('return_hi')
        self.assertEqual('hi', result)

    def test_class_remote_command_execute_autogen_method(self):
        result = self.test_class_interface_instance.test_interface.\
            return_hi()
        self.assertEqual('hi', result)


class TestPillarQueueThread(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_class_instance = TestClass()
        self.test_class_instance.shutdown_callback.set()

    @SkipTest
    async def test_run_queue_commands_calls_command_queue_get(self):
        self.test_class_instance.command_queue.put(QueueCommand(
            'return_hi'))
        await self.test_class_instance.run_queue_commands()
        result = self.test_class_instance.output_queue.get_nowait()
        print(result)
