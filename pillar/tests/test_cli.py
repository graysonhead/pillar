from unittest import TestCase
from ..cli import CLI
import os
import yaml
from pathlib import Path


class TestCLIBootstrap(TestCase):

    def setUp(self) -> None:
        self.cli = CLI(
            [
                '--config',
                'pillar/tests/data/cli_test/cli_test.yaml',
                'bootstrap'
            ]
        )

    def test_cli_load_config(self):
        self.assertEqual('pillar/tests/data/cli_test',
                         self.cli.config.get_value('config_directory'))


class TestCLIGenConf(TestCase):

    def setUp(self) -> None:
        self.cli = CLI([
            '--config',
            'pillar/tests/data/cli_test/generated_config.yaml'
        ])
        self.path = str(
            Path('pillar/tests/data/cli_test/generated_config.yaml')
        )

    def tearDown(self) -> None:
        os.remove(self.path)

    def test_cli_generate_on_file_not_exists(self):
        with open(self.path, 'r') as file:
            generated_config = yaml.load(file, Loader=yaml.FullLoader)
        print(generated_config)
        for key, value in generated_config.items():
            self.assertEqual(value, self.cli.config.get_value(key))
