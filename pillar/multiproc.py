from multiprocessing import Process, Queue, Event
from queue import Empty
import asyncio
import logging
import time
from uuid import uuid4


class QueueCommand:
    def __init__(self, command_name: str, *args, **kwargs):
        self.logger = logging.getLogger(f"<{self.__class__.__name__}>")
        self.command_name = command_name
        self.args = args
        self.kwargs = kwargs
        self.id = uuid4()


class PillarQueueMethodsRegister:
    methods = {}

    @classmethod
    def register_method(cls, method: callable):
        cls.methods.update({method.__name__: method})
        return method

    @classmethod
    def get_methods(cls):
        return cls.methods


class PillarQueueCommandCallable:

    def __init__(self, command: str, parent_instance):
        self.command = command
        self.parent_instance = parent_instance

    def __call__(self, *args, **kwargs):
        return self.parent_instance.command(self.command,
                                            *args, **kwargs)


class PillarQueueThread(Process):
    command_queue = Queue()
    output_queue = Queue()
    shutdown_callback = Event()
    methods_register_class = None

    def __init__(self):
        self.loop = None
        super().__init__()

    async def run_queue_commands(self):
        while True:
            try:
                command = self.command_queue.get_nowait()
                args = command.args
                kwargs = command.kwargs
                output = self.methods_register_class.\
                    methods[command.command_name](
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
                break

    def exit(self, timeout: int = None):
        self.shutdown_callback.set()
        self.join(timeout=timeout)
        self.close()

    def run(self):
        self.loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.run_queue_commands())
        self.loop.run_forever()


class PillarQueueInterface:

    def __init__(self,
                 queue_thread_class: PillarQueueThread
                 ):
        self.queue_thread_class = queue_thread_class
        self.method_register = queue_thread_class.methods_register_class
        self.setup_command_methods()

    def setup_command_methods(self):
        for command in self.method_register.get_methods():
            setattr(self, command, PillarQueueCommandCallable(command, self))

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


class PillarQueueClientMixIn:
    queue_thread_class = None
    interface_name = None

    def __init__(self):
        setattr(self,
                self.interface_name,
                PillarQueueInterface(
                    self.queue_thread_class)
                )
