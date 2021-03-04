from .config import PillardConfig, get_ipfs_config_options
from .ipfs import IPFSWorker, IPFSClient
from .db import PillarDBWorker
from .identity import NodeIdentityMixIn, Node
from .keymanager import KeyManager, KeyManagerCommandQueueMixIn, PillarKeyType
from .IPRPC.cid_messenger import CIDMessenger
from .multiproc import MixedClass
from .keymanager import EncryptionHelper
from .IPRPC.channel import IPRPCChannel
from pathos.helpers import mp as pmp

import logging
import multiprocessing
import signal
import time


class ProcessManager:
    process_type = multiprocessing.Process

    def __init__(self):
        self.logger = logging.getLogger(self.__repr__())
        self.processes = []
        self.initialize_processes()

    def initialize_processes(self):
        pass

    def check_processes(self):
        pass

    def start_all_processes(self):
        for process in self.processes:
            if not process.is_alive():
                if not process.exitcode:
                    self.logger.info(f"Starting process {process}")
                    process.start()

    def stop_all_processes(self, join_timeout: int = 5):
        for process in self.processes:
            self.logger.info(f"Sending shutdown event to {process}")
            process.shutdown_callback.set()
        for process in self.processes:
            process.join(join_timeout)
            if process.exitcode is None:
                process.terminate()

    def prune_dead_processes(self):
        processes_to_remove = []
        for process in self.processes:
            if not process.is_alive():
                if process.exitcode is not None:
                    processes_to_remove.append(process)

        for process in processes_to_remove:
            self.logger.warning(f"{process} died unexpectedly and was pruned")
            process.join()
            self.processes.remove(process)
        if processes_to_remove:
            self.check_processes()


class IPFSWorkerManager(ProcessManager):

    def __init__(self, config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.config = config
        super().__init__()

    def get_ipfs_config(self):
        return get_ipfs_config_options(self.config)

    def get_new_process(self):
        ipfs_client = IPFSClient(aioipfs_config=self.get_ipfs_config())
        return IPFSWorker(self.command_queue,
                          self.output_queue,
                          ipfs_client=ipfs_client)

    def initialize_processes(self):
        for i in range(self.config.get_value('ipfs_workers')):
            self.processes.append(self.get_new_process())

    def check_processes(self):
        number_of_processes = len(self.processes)
        desired_processes = self.config.get_value('ipfs_workers')
        if number_of_processes < desired_processes:
            missing_processes = desired_processes - number_of_processes
            for i in range(missing_processes):
                self.processes.append(self.get_new_process())
            self.start_all_processes()


class DBWorkerManager(ProcessManager):

    def __init__(self, config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.config = config
        super().__init__()

    def get_new_process(self):
        return PillarDBWorker(self.config,
                              self.command_queue,
                              self.output_queue)

    def initialize_processes(self):
        self.processes.append(self.get_new_process())

    def check_processes(self):
        if not self.processes:
            self.processes.append(self.get_new_process())
            self.start_all_processes()


class NodeWorkerManager(ProcessManager):

    def __init__(self,
                 config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.config = config
        super().__init__()

    def initialize_processes(self):
        self.processes.append(
            Node.get_local_instance(self.config,
                                    self.command_queue,
                                    self.output_queue)
        )

    def check_processes(self):
        if not self.processes:
            self.initialize_processes()


class KeyManagerWorkerManager(ProcessManager):

    def __init__(self, config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue,
                 bootstrap: bool = False):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.bootstrap = bootstrap
        self.config = config
        super().__init__()

    def initialize_processes(self):
        self.processes.append(
            KeyManager.get_local_instance(
                self.config,
                self.command_queue,
                self.output_queue
            ))

    def check_processes(self):
        if not self.processes:
            self.initialize_processes()


class CidMessengerWorkerManager(ProcessManager):

    def __init__(self,
                 config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.config = config
        super().__init__()

    def initialize_processes(self):
        self.processes.append(
            CIDMessenger(PillarKeyType.NODE_SUBKEY,
                         self.config,
                         self.command_queue,
                         self.output_queue)
        )

    def check_processes(self):
        if not self.processes:
            self.initialize_processes()


class ChannelManagerInterface(KeyManagerCommandQueueMixIn,
                              NodeIdentityMixIn,
                              metaclass=MixedClass):
    pass


class ChannelManager(ProcessManager):

    def __init__(self,
                 config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.interface = ChannelManagerInterface(str(self),
                                                 command_queue=command_queue,
                                                 output_queue=output_queue)
        self.config = config
        super().__init__()

    def check_processes(self):
        keys = self.interface.key_manager.get_keys()
        our_fingerprint = self.interface.node_identity.get_fingerprint()
        for key in keys:
            try:
                next(
                    filter(
                        lambda x: x.peer_id == key.fingerprint, self.processes
                           )
                )
            except StopIteration:
                self.processes.append(IPRPCChannel(
                    our_fingerprint,
                    peer_fingerprint=key.fingerprint,
                    encryption_helper=EncryptionHelper(
                        PillarKeyType.NODE_SUBKEY,
                        self.command_queue,
                        self.output_queue),
                    # TODO: IPFS Configuration
                ))
        for channel in self.processes:
            try:
                next(filter(lambda x: x.fingerprint == channel.peer_id, keys))
            except StopIteration:
                channel.terminate()

        self.start_all_processes()


class PillarDaemon:

    def __init__(self,
                 config: PillardConfig):
        self.queue_manager = pmp.Manager()
        self.shared_command_queue = self.queue_manager.Queue()
        self.shared_output_queue = self.queue_manager.Queue()
        self.stop_signal = multiprocessing.Event()
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.process_managers = []
        signal.signal(signal.SIGINT, self.stop)

    def start_stage_1(self):
        managers = [DBWorkerManager(self.config,
                                    self.shared_command_queue,
                                    self.shared_output_queue),
                    IPFSWorkerManager(self.config,
                                      self.shared_command_queue,
                                      self.shared_output_queue)]
        for manager in managers:
            self.process_managers.append(manager)
            manager.start_all_processes()
        print("Stage 1 complete")

    def start_stage_2(self):
        managers = [KeyManagerWorkerManager(self.config,
                                            self.shared_command_queue,
                                            self.shared_output_queue),
                    NodeWorkerManager(self.config,
                                      self.shared_command_queue,
                                      self.shared_output_queue)]
        for manager in managers:
            self.process_managers.append(manager)
            manager.start_all_processes()
        print("Stage 2 complete")

    def start_stage_3(self):
        managers = [
            CidMessengerWorkerManager(self.config,
                                      self.shared_command_queue,
                                      self.shared_output_queue),
            ChannelManager(self.config,
                           command_queue=self.shared_command_queue,
                           output_queue=self.shared_output_queue)]
        for manager in managers:
            self.process_managers.append(manager)
            manager.start_all_processes()
        print("Startup complete")

    def start(self):
        self.start_stage_1()
        time.sleep(5)
        self.start_stage_2()
        time.sleep(5)
        self.start_stage_3()

    def start_housekeeping(self):
        while not self.stop_signal.is_set():
            self.process_housekeeping()
            if self.stop_signal.is_set():
                break
            time.sleep(10)

    def process_housekeeping(self):
        for manager in self.process_managers:
            manager.check_processes()

    def stop(self, *args):
        if not self.stop_signal.is_set():
            self.stop_signal.set()
            for manager in self.process_managers:
                manager.stop_all_processes()

    def __del__(self):
        self.stop()

    def __repr__(self):
        return "<PillarDaemon>"
