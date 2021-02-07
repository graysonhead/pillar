from pillar.config import PillardConfig
from pillar.simple_daemon import Daemon
from unittest import TestCase
from unittest.mock import patch, MagicMock


class TestSimpleDaemon(TestCase):
    def test_instantiate(self):
        config = PillardConfig(config_directory="/this/shouldnt/exist")
        Daemon(config)


class MoreTestSimpleDaemon(TestCase):
    def setUp(self):
        self.config = PillardConfig(config_directory="/this/shouldnt/exist")
        self.daemon = Daemon(self.config)

    @patch('multiprocessing.Process.run', new_callable=MagicMock)
    @patch('pillar.multiproc.PillarWorkerThread.run', new_callable=MagicMock)
    def test_pre_run(self, *args):
        self.daemon.pre_run()
        assert(True)

    @patch('multiprocessing.Process.run', new_callable=MagicMock)
    @patch('pillar.multiproc.PillarWorkerThread.run', new_callable=MagicMock)
    @patch('pillar.multiproc.PillarWorkerThread.exit', new_callable=MagicMock)
    def test_shutdown_routine(self, *args):
        self.daemon.pre_run()
        self.daemon.shutdown_routine()
        assert(True)
