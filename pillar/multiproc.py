from pillar.exceptions import DebugWDTTimeout
from multiprocessing import Process, Event
from queue import Empty
import asyncio
import logging
import time
import inspect
import traceback
from uuid import uuid4


class DebugWDT(Process):
    def __init__(self, timeout):
        self.timeout = timeout
        self.alarm = Event()
        self.logged = False
        super().__init__()

    def run(self):
        import time
        i = self.timeout
        while i > 0:
            i -= 1
            time.sleep(1)

        self.alarm.set()


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
        self.logger.debug(f"running command {command_name} id {self.id}")


class PillarThreadMethodsRegister:
    """
    This class keeps track of registered methods so they can be added to the
    PillarThreadInterface dynamically.
    """

    def __init__(self):
        self.methods = {}

    def register_method(self, method: callable):
        self.methods.update({method.__name__: method})
        return method

    def get_methods(self):
        return self.methods


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

    The methods_register class attribute must be set to the
    PillarThreadMethodsRegister subclass used for this interface

    This inherits multiprocess.Process, and is started with self.start()

    Any class that inherits this one must supply the following class
    attributes:
    command_queue = Queue()
    output_queue = Queue()
    shutdown_callback = Event()
    """
    command_queue = None
    output_queue = None
    shutdown_callback = None
    methods_register = None

    def __init__(self):
        self.loop = None
        super().__init__()
        if not hasattr(self, "logger"):
            self.logger = logging.getLogger(f"<{self.__class__.__name__}>")

    def each_loop(self):
        if self.__class__.__name__ == "KeyManager":
            pass
        # self.logger.info(".")

    async def run_queue_commands(self):
        """
        Pulls commands from the queue, and runs matching methods on the class
        """
        while True:
            self.each_loop()
            try:
                command = self.command_queue.get_nowait()
                self.logger.debug(f"receved command {command.command_name}")
                args = command.args
                kwargs = command.kwargs
                method = self.methods_register. \
                    methods[command.command_name]
                try:
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
                    self.logger.debug(f"Enqueuing output: {output}")
                    self.output_queue.put(
                        {command.id: output}
                    )
                except Exception as e:
                    self.logger.warn(
                        ''.join(traceback.format_exception(
                            None, e, e.__traceback__)))
                    self.output_queue.put(
                        {command.id: e}
                    )

            except Empty:
                await asyncio.sleep(0.01)
            if self.shutdown_callback.is_set():
                self.shutdown_routine()
                if self.loop:
                    self.loop.stop()
                break

    def exit(self, *args):
        self.logger.info("shutting down")
        self.shutdown_callback.set()

    def shutdown_routine(self):
        """
        Override to run last minute commnands from within the child
        process.
        """

    def pre_run(self):
        """override to execute prior to process loop"""

    def run(self):
        """
        This runs the worker loop, and is called in a subprocess by the
        self.start() method
        """
        self.pre_run()
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
    debug = False

    def __init__(self,
                 queue_thread_class: PillarWorkerThread
                 ):
        self.queue_thread_class = queue_thread_class
        self.method_register = queue_thread_class.methods_register
        self.setup_command_methods()
        self.logger = logging.getLogger(f"<{self.__class__.__name__}>")

    def setup_command_methods(self):
        for command in self.method_register.get_methods():
            setattr(self, command, PillarThreadCommandCallable(command, self))

    def command(self, command_name: str, *args, **kwargs):
        command = QueueCommand(command_name, *args, **kwargs)
        self.queue_thread_class.command_queue.put(command)
        return self.get_command_output(command.id)

    def get_command_output(self, uuid: uuid4, only_once: bool = False):
        debug_wdt = DebugWDT(1)
        debug_wdt.start()
        output_queue = self.queue_thread_class.output_queue
        ret = None
        found = False
        while not found:
            if self.debug and debug_wdt.alarm.is_set():
                try:
                    raise DebugWDTTimeout
                except Exception as e:
                    if not debug_wdt.logged:
                        debug_wdt.logged = True
                        self.logger.warn(
                            ''.join(traceback.format_exception(
                                None, e, e.__traceback__)))
            try:
                output = output_queue.get_nowait()
                for id, output in output.items():
                    if type(output) is Exception:
                        raise output
                    if id == uuid:
                        self.logger.debug(
                            f"got command output for command id {uuid}")
                        ret = output
                        found = True
                    else:
                        output_queue.put({id: output})
            except Empty:
                if only_once:
                    break
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

    def __init__(self, interface_name, queue_thread_class):
        setattr(self,
                interface_name,
                PillarThreadInterface(
                    queue_thread_class)
                )


class MixedClass(type):
    def __new__(cls, name, bases, classdict):
        classinit = classdict.get('__init__')

        def __init__(self, *args, **kwargs):
            for base in type(self).__bases__:
                if issubclass(base, PillarThreadMixIn):
                    base.__init__(self, base.interface_name,
                                  base.queue_thread_class)
                else:
                    base.__init__(self, *args, **kwargs)
            if classinit:
                classinit(self, *args, **kwargs)

        classdict['__init__'] = __init__
        return type.__new__(cls, name, bases, classdict)
