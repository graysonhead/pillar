import asynctest
from ..multiproc import PillarQueueMethodsRegister, \
    PillarQueueThread, \
    PillarQueueClientMixIn, \
    QueueCommand
from unittest import SkipTest


class TestClassRegister(PillarQueueMethodsRegister):
    pass


class TestClass(PillarQueueThread):
    methods_register_class = TestClassRegister

    @TestClassRegister.register_method
    def return_hi(self):
        return "hi"


class TestClassMixIn(PillarQueueClientMixIn):
    queue_thread_class = TestClass
    interface_name = "test_interface"


class TestMultiProc(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_class_instance = TestClass()
        self.test_class_interface_instance = TestClassMixIn()
        self.test_class_instance.start()

    def tearDown(self) -> None:
        self.test_class_instance.terminate()

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
