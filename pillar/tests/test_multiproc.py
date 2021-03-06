"""
IMPORTANT: This file is referenced via line numbers in the documentation on the
"Development Guide > Threading Model" page. If you modify this file, please
ensure that the examples on this page are still captured correctly as their
line numbers will have changed!
"""
import asynctest
import time
from uuid import uuid4
from unittest.mock import MagicMock
from ..multiproc import PillarThreadMethodsRegister, \
    PillarWorkerThread, \
    PillarThreadMixIn, \
    QueueCommand, \
    MixedClass
from multiprocessing import Queue, Event
import multiprocessing as mp

test_class_register = PillarThreadMethodsRegister()
test_class_2_register = PillarThreadMethodsRegister()


class TestClass(PillarWorkerThread):
    """
    This is the class that will spawn one or more worker threads where
    commands will actually be run when interface methods are called.

    The method register class must be specified as a class attribute as below.
    """
    command_queue = Queue()
    output_queue = Queue()
    shutdown_callback = Event()
    methods_register = test_class_register

    @test_class_register.register_method
    def return_hi(self):
        """
        The above decorator allows the interface added by TestClassMixIn to
        trigger this method from a remote process and retrieve it's output.
        """
        return "hi"

    @test_class_register.register_method
    async def return_hi_async(self):
        """
        Async methods work as well
        """
        return "hi"


class TestClass2(PillarWorkerThread):
    command_queue = Queue()
    output_queue = Queue()
    shutdown_callback = Event()
    methods_register = test_class_2_register

    @test_class_2_register.register_method
    def return_hi_2(self):
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


class TestClass2MixIn(PillarThreadMixIn):
    """
    This class is inherited by the class that interacts with TestClass.

    The queue_thread_class attribute must contain the target worker thread
    class so the queues and methods of the interface can be set up correctly.

    Additionally, the interface_name must be specified, and will determine
    the attribute name of the interface on the parent class.
    """
    queue_thread_class = TestClass2
    interface_name = "test_interface_2"


class MultipleMixInInterfaces(TestClassMixIn,
                              TestClass2MixIn,
                              metaclass=MixedClass):
    pass


class TestMultiProcBehavior(asynctest.TestCase):

    def setUp(self) -> None:
        self.instance = TestClass()

    def test_exit_behavior(self):
        self.instance.shutdown_callback.set = MagicMock()
        self.instance.exit()
        self.instance.shutdown_callback.set.assert_called()


class TestMultiProc(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_class_instance = TestClass()
        self.test_class_instance.shutdown_callback.set()

    def test_class_method_registered(self):
        self.assertIn('return_hi', test_class_register.methods.keys())

    async def test_class_remote_command_execute(self):
        command = QueueCommand('return_hi', 'TestClass', str(self))
        self.test_class_instance.command_queue.put(command)
        time.sleep(.01)
        await self.test_class_instance.run_queue_commands()
        time.sleep(.01)
        result = self.test_class_instance.output_queue.get_nowait()
        self.assertEqual('hi', result[command.id])

    async def test_class_remote_command_execute_async(self):
        command = QueueCommand('return_hi_async', 'TestClass', str(self))
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
        manager = mp.Manager()
        self.command_queue = manager.Queue()
        self.output_queue = manager.Queue()
        self.interface = TestClassMixIn(TestClassMixIn.interface_name,
                                        TestClassMixIn.queue_thread_class,
                                        str(self),
                                        command_queue=self.command_queue,
                                        output_queue=self.output_queue)

    def test_class_remote_command_execute_autogen_method(self):
        self.interface.test_interface.\
            get_command_output = echo_command_output
        return_value = self.interface.test_interface.\
            return_hi()
        self.assertIn('somevalue', return_value.values())

    def test_get_return_value_from_queue(self):
        command = QueueCommand('fake_command', 'fake_class', 'fake_requestor')
        self.output_queue.put(
            {command.id: "test_value"}
        )
        return_value = self.interface.test_interface.\
            get_command_output(command, only_once=True)
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


class TestMultipleMixInInterfacesOnSameClass(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_class_instance = TestClass()
        self.test_class_instance_2 = TestClass2()
        self.manager = mp.Manager()
        self.command_queue = self.manager.Queue()
        self.output_queue = self.manager.Queue()
        self.fake_plugin = MultipleMixInInterfaces(
            str(self),
            self.command_queue,
            self.output_queue
        )

    def test_both_interfaces_created(self):
        self.assertEqual(True, hasattr(
            self.fake_plugin, TestClassMixIn.interface_name))
        self.assertEqual(True, hasattr(
            self.fake_plugin, TestClass2MixIn.interface_name))

    def test_interfaces_have_correct_methods(self):
        interface_1 = getattr(self.fake_plugin,
                              TestClassMixIn.interface_name)
        interface_2 = getattr(self.fake_plugin,
                              TestClass2MixIn.interface_name)
        self.assertEqual(True, hasattr(interface_1, "return_hi"))
        self.assertEqual(True, hasattr(interface_1, "return_hi_async"))
        self.assertEqual(False, hasattr(interface_1, "return_hi_2"))
        self.assertEqual(True, hasattr(interface_2, "return_hi_2"))


test_managed_queue_register = PillarThreadMethodsRegister()


class TestMQRWorker(PillarWorkerThread):
    methods_register = test_managed_queue_register

    @test_managed_queue_register.register_method
    def return_hi(self):
        return "hi"


class TestMQRMixIn(PillarThreadMixIn):
    queue_thread_class = TestMQRWorker
    interface_name = "mqr"


class MQRInterface(TestMQRMixIn,
                   metaclass=MixedClass):
    pass


class TestMQR(asynctest.TestCase):

    def setUp(self) -> None:
        manager = mp.Manager()
        self.command_queue = manager.Queue()
        self.output_queue = manager.Queue()
        self.worker = TestMQRWorker(command_queue=self.command_queue,
                                    output_queue=self.output_queue)
        self.interface = MQRInterface(str(self),
                                      command_queue=self.command_queue,
                                      output_queue=self.output_queue)
        self.worker.shutdown_callback.set()

    def test_queue_connection(self):
        self.interface.mqr.command_queue.put('test')
        result = self.worker.command_queue.get()
        self.assertEqual('test', result)

    def test_mqr_put_on_provided_queue(self):
        self.interface.mqr.command_queue.put = MagicMock()
        self.interface.mqr.get_command_output = MagicMock()
        self.interface.mqr.return_hi()
        self.interface.mqr.command_queue.put.assert_called()
        self.interface.mqr.get_command_output.assert_called()

    async def test_mqr_runs_remote_command(self):
        command = QueueCommand('return_hi',
                               self.worker.__class__.__name__,
                               str(self.interface))
        self.interface.mqr.command_queue.put(command)
        time.sleep(.01)
        await self.worker.run_queue_commands()
        time.sleep(.01)
        result = self.worker.output_queue.get_nowait()
        self.assertEqual('hi', result[command.id])

    async def test_mqr_returns_wrong_task_to_queue(self):
        command = QueueCommand('return_hi', 'wrong_class', str(self.interface))
        self.interface.mqr.command_queue.put(command)
        time.sleep(.01)
        await self.worker.run_queue_commands()
        time.sleep(.01)
        # This shouldn't raise Empty because the worker returned the command
        self.interface.mqr.command_queue.get_nowait()
