from pillar.config import PillardConfig
from pillar.simple_daemon import Daemon
from unittest import TestCase


class TestSimpleDaemon(TestCase):
    def test_instantiate(self):
        config = PillardConfig(config_directory="/this/shouldnt/exist")
        Daemon(config)
