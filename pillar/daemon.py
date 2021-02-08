from .config import PillardConfig, get_ipfs_config_options
from .ipfs import IPFSWorker, IPFSClient
from .db import PillarDBWorker
from .async_untils import handler_loop
import logging
import multiprocessing
import asyncio


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

    def __init__(self, config: PillardConfig):
        self.config = config
        super().__init__()

    def get_ipfs_config(self):
        return get_ipfs_config_options(self.config)

    def get_new_process(self):
        ipfs_client = IPFSClient(aioipfs_config=self.get_ipfs_config())
        return IPFSWorker(ipfs_client=ipfs_client)

    def initialize_processes(self):
        for i in range(self.config.get_value('ipfs_worker_manager')):
            self.processes.append(self.get_new_process())

    def check_processes(self):
        number_of_processes = len(self.processes)
        desired_processes = self.config.get_value('ipfs_worker_manager')
        if number_of_processes < desired_processes:
            missing_processes = desired_processes - number_of_processes
            for i in range(missing_processes):
                self.processes.append(self.get_new_process())
            self.start_all_processes()


class DBWorkerManager(ProcessManager):

    def __init__(self, config: PillardConfig):
        self.config = config
        super().__init__()

    def get_new_process(self):
        return PillarDBWorker(self.config)

    def initialize_processes(self):
        self.processes.append(self.get_new_process())

    def check_processes(self):
        if not self.processes:
            self.processes.append(self.get_new_process())
            self.start_all_processes()


class PillarDaemon:

    def __init__(self,
                 config: PillardConfig):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.process_managers = []
        self.process_managers.append(IPFSWorkerManager(self.config))
        self.process_managers.append(DBWorkerManager(self.config))
        self.loop = asyncio.get_event_loop()

    def start(self):
        for manager in self.process_managers:
            manager.start_all_processes()

    def start_housekeeping(self, run_once=False):
        tasks = asyncio.gather(
            handler_loop(
                self.process_housekeeping,
                sleep=5,
                run_once=run_once
            )
        )
        try:
            self.loop.run_until_complete(tasks)
        except KeyboardInterrupt:
            print("Caught keyboard interrupt, Shutting down.")
            self.stop()
            tasks.cancel()
            self.loop.run_forever()
            tasks.exception()
        finally:
            self.loop.close()

    async def process_housekeeping(self):
        self.logger.info("Process housekeeping ran")
        for manager in self.process_managers:
            manager.check_processes()

    def stop(self):
        for manager in self.process_managers:
            manager.stop_all_processes()

    def __del__(self):
        self.stop()

    def __repr__(self):
        return "<PillarDaemon>"
