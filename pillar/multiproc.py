from multiprocessing import Process, Queue, Event
from queue import Empty
import asyncio
import logging
import time
import inspect
from uuid import uuid4


class QueueCommand:
    """
    This is the base class for commands sent from a PillarThreadMixIn. This
    is sent over the command_queue of the PillarThreadInterface to one or more
    PillarWorkerThreads
    """
    def __init__(self, command_name: str, *args, **kwargs):
        self.logger = logging.getLogger(f"<{self.__class__.__name__}>")
        self.command_name = command_name
        self.args = args
        self.kwargs = kwargs
        self.id = uuid4()


class PillarThreadMethodsRegister:
    """
    This class keeps track of registered methods so they can be added to the
    PillarThreadInterface dynamically.
    """
    methods = {}

    @classmethod
    def register_method(cls, method: callable):
        cls.methods.update({method.__name__: method})
        return method

    @classmethod
    def get_methods(cls):
        return cls.methods


class PillarThreadCommandCallable:
    """
    This class is added as an attribute for each method in the
    PillarThreadMethodsRegister, to imitate those methods on the interface
    """
    def __init__(self, command: str, parent_instance):
        self.command = command
        self.parent_instance = parent_instance

    def __call__(self, *args, **kwargs):
        return self.parent_instance.command(self.command,
                                            *args, **kwargs)


class PillarWorkerThread(Process):
    """
    This class is inherited by the worker threads that willl process requests
    Any methods added to the registry via decorator will be callable by
    the PillarThreadInterface

    The methods_register_class class attribute must be set to the
    PillarThreadMethodsRegister subclass used for this interface

    This inherits multiprocess.Process, and is started with self.start()
    """
    command_queue = Queue()
    output_queue = Queue()
    shutdown_callback = Event()
    methods_register_class = None

    def __init__(self):
        self.loop = None
        super().__init__()

    async def run_queue_commands(self):
        """
        Pulls commands from the queue, and runs matching methods on the class
        """
        while True:
            try:
                command = self.command_queue.get_nowait()
                args = command.args
                kwargs = command.kwargs
                method = self.methods_register_class. \
                    methods[command.command_name]
                if inspect.iscoroutinefunction(method):
                    output = await method(
                        self,
                        *args,
                        **kwargs
                    )
                else:
                    output = method(
                        self,
                        *args,
                        **kwargs
                    )
                self.output_queue.put(
                    {command.id: output}
                )
            except Empty:
                await asyncio.sleep(0.01)
            if self.shutdown_callback.is_set():
                self.loop.stop()
                break

    def exit(self, timeout: int = 5):
        self.shutdown_callback.set()
        self.join(timeout=timeout)
        self.close()

    def __del__(self):
        try:
            if self.is_alive():
                self.exit()
        except ValueError:
            pass
        if self.loop:
            self.loop.close()

    def run(self):
        """
        This runs the worker loop, and is called in a subprocess by the
        self.start() method
        """
        self.loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.run_queue_commands())
        self.loop.run_forever()


class PillarThreadInterface:
    """
    This class is added to a parent class that subclasses the
    PillarThreadMixIn class. Any registered methods on the PillarThreadWorker
    class will be added to this class and are callable, but will be run
    transparently on the worker as opposed to the local class.
    """
    def __init__(self,
                 queue_thread_class: PillarWorkerThread
                 ):
        self.queue_thread_class = queue_thread_class
        self.method_register = queue_thread_class.methods_register_class
        self.setup_command_methods()

    def setup_command_methods(self):
        for command in self.method_register.get_methods():
            setattr(self, command, PillarThreadCommandCallable(command, self))

    def command(self, command_name: str, *args, **kwargs):
        command = QueueCommand(command_name, *args, **kwargs)
        self.queue_thread_class.command_queue.put(command)
        return self.get_command_output(command.id)

    def get_command_output(self, uuid: uuid4):
        output_queue = self.queue_thread_class.output_queue
        ret = None
        found = False
        while not found:
            try:
                output = output_queue.get_nowait()
                for id, output in output.items():
                    if id == uuid:
                        ret = output
                        found = True
                    else:
                        output_queue.put({id: output})
            except Empty:
                time.sleep(.01)
        return ret


class PillarThreadMixIn:
    """
    This class is inherited by the plugin/class that needs to run commands
    on the remote worker, the queue_thread_class must be set to the
    PillarWorkerThread class, and interface_name must be set to the name of
    the attribute on the class that the interface will be created as
    """
    queue_thread_class = None
    interface_name = None

    def __init__(self):
        setattr(self,
                self.interface_name,
                PillarThreadInterface(
                    self.queue_thread_class)
                )
