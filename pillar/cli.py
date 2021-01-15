import argparse
from pillar.config import Config
from argparse import Namespace
import logging
from pillar.db import PillarDataStore
from pillar.keymanager import KeyManager
from pillar.bootstrap import Bootstrapper
from pathlib import Path


class CLI:

    def __init__(self, args: list):
        self.logger = logging.getLogger(self.__repr__())
        self.args = self.parse_args(args)
        if self.args.verb:
            logging.basicConfig(level=getattr(logging, self.args.verb))
        if not self.args.sub_command == 'bootstrap':
            self.config = self.get_config(self.args.config)
            self.pds = PillarDataStore(self.config)
            self.key_manager = KeyManager(self.config)
            self.user = None

    def run(self):
        if self.args.sub_command == 'bootstrap':
            self.bootstrap()

    def bootstrap(self):
        bootstrap = Bootstrapper(
            self.args
        )
        bootstrap.bootstrap()

    def parse_args(self, args: list) -> Namespace:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="sub_command")
        bootstrap = subparsers.add_parser("bootstrap",
                                          help="Bootstrap a pillar node")
        bootstrap.add_argument("--purge",
                               help="Removes and re-creates databases and"
                                    " config files.",
                               action='store_true')
        parser.add_argument("--config",
                            default='/etc/pillar/pillar.yaml')
        parser.add_argument("--verb",
                            default="WARNING",
                            choices=["INFO", "DEBUG", "WARNING"])
        return parser.parse_args(args)

    def get_config(self, config_path: str) -> Config:
        path = Path(config_path).resolve()
        self.logger.info(f"Loading config file from {config_path}")
        try:
            config = Config.load_from_yaml(str(path))
        except FileNotFoundError:
            config = Config()
            self.logger.info(f"Didn't find config file, created one at"
                             f" {config_path}")

        self.logger.info(f"Loaded options: {config.get_dict()}")
        return config

    def __repr__(self):
        return "<CLI>"
