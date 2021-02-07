from pillar.config import PillardConfig, get_ipfs_config_options
from pillar.ipfs import IPFSWorker, IPFSClient
import logging
import multiprocessing
from time import sleep


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

    def __init__(self, config: PillardConfig):
        self.config = config
        super().__init__()

    def get_ipfs_config(self):
        return get_ipfs_config_options(self.config)

    def get_new_process(self):
        ipfs_client = IPFSClient(aioipfs_config=self.get_ipfs_config())
        return IPFSWorker(ipfs_client=ipfs_client)

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


class PillarDaemon:

    def __init__(self,
                 config: PillardConfig):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.ipfs_workers = IPFSWorkerManager(self.config)

    def start(self, break_immediately=False):
        self.ipfs_workers.start_all_processes()
        while True:
            if break_immediately:
                break
            sleep(1)

    def stop(self):
        self.ipfs_workers.stop_all_processes()

    def __del__(self):
        self.stop()

    def __repr__(self):
        return "<PillarDaemon>"
