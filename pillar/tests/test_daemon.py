from unittest import TestCase
from unittest.mock import MagicMock, patch
from ..daemon import ProcessManager, \
    IPFSWorkerManager, \
    PillarDaemon, \
    DBWorkerManager, \
    NodeWorkerManager
from ..config import PillardConfig
import asynctest


class TestProcessManagerBase(TestCase):

    def setUp(self) -> None:
        self.pm = ProcessManager()

    def test_starts_all_processes(self):
        process_1 = MagicMock()
        process_2 = MagicMock()
        process_1.is_alive.return_value = False
        process_1.exitcode = None
        process_2.is_alive.return_value = False
        process_2.exitcode = None
        self.pm.processes.append(process_1)
        self.pm.processes.append(process_2)
        self.pm.start_all_processes()
        process_1.start.assert_called()
        process_2.start.assert_called()

    def test_starts_only_unalive_processes(self):
        process_1 = MagicMock()
        process_2 = MagicMock()
        process_1.is_alive.return_value = False
        process_1.exitcode = None
        process_2.is_alive.return_value = True
        self.pm.processes.append(process_1)
        self.pm.processes.append(process_2)
        self.pm.start_all_processes()
        process_1.start.assert_called()
        process_2.start.assert_not_called()

    def test_doesnt_start_dead_processes_with_exitcode(self):
        process = MagicMock()
        process.is_alive.return_value = False
        process.exitcode = None
        self.pm.start_all_processes()
        process.start.assert_not_called()

    def test_prune_dead_processes(self):
        process = MagicMock()
        process.is_alive.return_value = False
        process.exitcode = 0
        self.pm.processes.append(process)
        self.pm.prune_dead_processes()
        process.join.assert_called()

    def test_new_processes_not_pruned(self):
        process = MagicMock()
        process.is_alive.return_value = False
        process.exitcode = None
        self.pm.processes.append(process)
        self.pm.prune_dead_processes()
        process.join.assert_not_called()

    def test_prune_calls_check_processes_when_process_removed(self):
        self.pm.check_processes = MagicMock()
        process = MagicMock()
        process.is_alive.return_value = False
        process.exitcode = 0
        self.pm.processes.append(process)
        self.pm.prune_dead_processes()
        self.pm.check_processes.assert_called()

    def test_prune_doesnt_call_check_processes_when_process_not_removed(self):
        self.pm.check_processes = MagicMock()
        self.pm.prune_dead_processes()
        self.pm.check_processes.assert_not_called()

    def test_stop_all_processes_normal(self):
        process = MagicMock()
        process.shutdown_callback = MagicMock()
        process.is_alive = True
        process.exitcode = 0
        self.pm.processes.append(process)
        self.pm.stop_all_processes(join_timeout=5)
        process.shutdown_callback.set.assert_called()
        process.join.assert_called_with(5)
        process.terminate.assert_not_called()

    def test_stop_unresponsive_process(self):
        process = MagicMock()
        process.shutdown_callback = MagicMock()
        process.is_alive = True
        process.exitcode = None
        self.pm.processes.append(process)
        self.pm.stop_all_processes()
        process.shutdown_callback.set.assert_called()
        process.join.assert_called()
        process.terminate.assert_called()


class TestIPFSWorkerManager(TestCase):

    def setUp(self) -> None:
        self.config = PillardConfig()
        self.pm = IPFSWorkerManager(self.config)

    @patch('pillar.ipfs.IPFSWorker')
    def test_create_initial_processes(self, mocked_worker):
        self.assertEqual(self.config.get_value('ipfs_workers'),
                         len(self.pm.processes))

    @patch('pillar.ipfs.IPFSWorker')
    def test_create_missing_processes(self, mocked_worker):
        self.pm.start_all_processes = MagicMock()
        self.pm.processes = []
        self.pm.check_processes()
        self.assertEqual(self.config.get_value('ipfs_workers'),
                         len(self.pm.processes))
        self.pm.start_all_processes.assert_called()


class TestDBWorkerManager(TestCase):

    def setUp(self) -> None:
        self.config = PillardConfig()
        self.pm = DBWorkerManager(self.config)

    @patch('pillar.db.PillarDBWorker')
    def test_create_initial_processes(self, mocked_worker):
        self.assertEqual(1, len(self.pm.processes))

    @patch('pillar.db.PillarDBWorker')
    def test_check_processes(self, mocked_worker):
        self.pm.start_all_processes = MagicMock()
        self.pm.processes = []
        self.pm.check_processes()
        self.assertEqual(1, len(self.pm.processes))
        self.pm.start_all_processes.assert_called()


class TestNodeWorkerManager(asynctest.TestCase):

    def setUp(self) -> None:
        self.config = PillardConfig()
        self.pm = NodeWorkerManager(self.config)

    @patch('pillar.identity.Node')
    def test_check_process_re_initialize_when_empty_processes(self, mocked_worker):
        self.pm.processes = []
        self.pm.initialize_processes = MagicMock()
        self.pm.check_processes()
        self.pm.initialize_processes.assert_called()


class TestPillarDaemon(asynctest.TestCase):

    def setUp(self, *args) -> None:
        self.config = PillardConfig()
        self.daemon = PillarDaemon(self.config)
        self.daemon.process_managers = []
        self.daemon.process_managers.append(MagicMock())

    def test_start_processes(self):
        self.daemon.start()
        for pm in self.daemon.process_managers:
            pm.start_all_processes.assert_called()

    def test_stop_processes(self):
        self.daemon.stop()
        for pm in self.daemon.process_managers:
            pm.stop_all_processes.assert_called()

    def test_daemon_repr(self):
        repr_string = self.daemon.__repr__()
        self.assertEqual("<PillarDaemon>", repr_string)

    def test_housekeeping(self):
        self.daemon.process_housekeeping()
        for pm in self.daemon.process_managers:
            pm.check_processes.assert_called()
