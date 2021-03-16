from pillar.exceptions import DebugWDTTimeout
from multiprocessing import Process, Event
from queue import Empty
import asyncio
import logging
import time
import inspect
import signal
import traceback
from uuid import uuid4
import multiprocessing as mp
import pgpy


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

    def __init__(self,
                 command_name: str,
                 worker_class: str,
                 requestor: str,
                 *args,
                 **kwargs):
        self.logger = logging.getLogger(f"<{self.__class__.__name__}>")
        self.worker_class = worker_class
        self.command_name = command_name
        self.requestor = requestor
        self.args = args
        self.kwargs = kwargs
        self.id = uuid4()
        self.logger.debug(f"running command {self.worker_class}.{command_name}"
                          f" id {self.id} requested by {self.requestor}")


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


class PillarWorkerThread(mp.Process):
    """
    This class is inherited by the worker threads that will process requests
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
    methods_register = None

    def __init__(self,
                 command_queue: mp.Queue = None,
                 output_queue: mp.Queue = None):
        self.loop = None
        if command_queue:
            self.command_queue = command_queue
        if output_queue:
            self.output_queue = output_queue
        super().__init__()
        if not hasattr(self, "logger"):
            self.logger = logging.getLogger(f"<{self.__class__.__name__}>")
        self.shutdown_callback = mp.Event()

    async def run_queue_commands(self):
        """
        Pulls commands from the queue, and runs matching methods on the class
        """
        while True:
            try:
                command = self.command_queue.get_nowait()
                if command.worker_class != self.__class__.__name__:
                    self.command_queue.put(command)
                else:
                    self.logger.debug(f"received command "
                                      f"{command.command_name}")
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

                        if isinstance(output, pgpy.PGPKey):
                            keyblob = bytes(output)
                            self.output_queue.put(
                                {command.id: {'PGPKey': keyblob}}
                            )

                        else:
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
            except BrokenPipeError or ConnectionResetError:
                self.logger.error(f"{self} shutting down due to broken pipe")
                self.shutdown_callback.set()
            if self.shutdown_callback.is_set():
                self.shutdown_routine()
                if self.loop:
                    self.loop.stop()
                break

    def exit(self, timeout: int = 5):
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
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.pre_run()
        self.loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.run_queue_commands())
        self.logger.info(f"Listening for commands on queue "
                         f"{self.command_queue}")
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
                 queue_thread_class: PillarWorkerThread,
                 parent_class_name: str,
                 command_queue: mp.Queue = None,
                 output_queue: mp.Queue = None,
                 ):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.worker_class_name = queue_thread_class.__name__
        self.queue_thread_class = queue_thread_class
        self.method_register = queue_thread_class.methods_register
        self.setup_command_methods()
        self.parent_class = parent_class_name
        self.logger = logging.getLogger(f"<{self.__class__.__name__}>")

    def setup_command_methods(self):
        for command in self.method_register.get_methods():
            setattr(self, command, PillarThreadCommandCallable(command, self))

    def command(self, command_name: str, *args, **kwargs):
        if self.command_queue:
            command_queue = self.command_queue
        else:
            command_queue = self.queue_thread_class.command_queue
        command = QueueCommand(command_name,
                               self.worker_class_name,
                               self.parent_class,
                               *args,
                               **kwargs)
        self.logger.info(f"Sending command "
                         f"{command.worker_class}.{command_name}")
        command_queue.put(command)
        return self.get_command_output(command)

    def get_command_output(self,
                           command: QueueCommand,
                           only_once: bool = False):
        debug_wdt = DebugWDT(1)
        debug_wdt.start()
        if self.output_queue:
            output_queue = self.output_queue
        else:
            output_queue = self.queue_thread_class.output_queue
        ret = None
        found = False
        while not found:
            if self.debug and debug_wdt.alarm.is_set():
                try:
                    raise DebugWDTTimeout(command)
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
                    if id == command.id:
                        self.logger.debug(
                            f"got command output for command id {id}")
                        if isinstance(output, dict):
                            if 'PGPKey' in output.keys():

                                ret, o = pgpy.PGPKey.from_blob(
                                    output['PGPKey'])
                            else:
                                ret = output
                        else:
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

    def __init__(self,
                 interface_name,
                 queue_thread_class,
                 parent_class_name,
                 command_queue: mp.Queue,
                 output_queue: mp.Queue):
        setattr(self,
                interface_name,
                PillarThreadInterface(
                    queue_thread_class,
                    parent_class_name,
                    command_queue=command_queue,
                    output_queue=output_queue
                )
                )


class MixedClass(type):
    def __new__(cls, name, bases, classdict):
        classinit = classdict.get('__init__')

        def __init__(self,
                     parent_class_name: str,
                     command_queue: mp.Queue = None,
                     output_queue: mp.Queue = None, *args, **kwargs):
            for base in type(self).__bases__:
                if issubclass(base, PillarThreadMixIn):
                    base.__init__(self, base.interface_name,
                                  base.queue_thread_class,
                                  parent_class_name,
                                  command_queue=command_queue,
                                  output_queue=output_queue)
                else:
                    base.__init__(self, *args, **kwargs)
            if classinit:
                classinit(self, *args, **kwargs)

        classdict['__init__'] = __init__
        return type.__new__(cls, name, bases, classdict)
