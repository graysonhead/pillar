import argparse
from pillar.config import Config
from argparse import Namespace
import logging
from pillar.db import PillarDataStore


class CLI:

    def __init__(self):
        self.logger = logging.getLogger(self.__repr__())
        self.args = self.parse_args()
        if self.args.verb:
            logging.basicConfig(level=getattr(logging, self.args.verb))
        self.config = self.get_config(self.args.config)
        self.pds = PillarDataStore(self.config)

    def run(self):
        if self.args.sub_command == 'bootstrap':
            print("Bootstrapping Pillar Node")
            self.create_database_if_not_exist()

    def parse_args(self) -> Namespace:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="sub_command")
        bootstrap = subparsers.add_parser("bootstrap",
                                          help="Bootstrap a pillar node")
        bootstrap.add_argument("--purge",
                               help="Removes and re-creates databases and"
                                    " config files.",
                               action='store_true')
        parser.add_argument("--config",
                            default="/etc/pillar/pillar.yaml")
        parser.add_argument("--verb",
                            default="WARNING",
                            choices=["INFO", "DEBUG", "WARNING"])
        return parser.parse_args()

    def get_config(self, config_path: str) -> Config:
        self.logger.info(f"Loading config file from {config_path}")
        try:
            config = Config.load_from_yaml(config_path)
        except FileNotFoundError:
            config = Config()
            config.generate_default(config_path)
            self.logger.info(f"Didn't find config file, created one at"
                             f" {config_path}")

        self.logger.info(f"Loaded options: {config.get_dict()}")
        return config

    def create_database_if_not_exist(self):
        if not self.pds.database_exists() and not self.args.purge:
            print("No database found, creating database")
            self.pds.create_database()
        elif self.pds.database_exists() and self.args.purge:
            print("Database found and --purge set, recreating database")
            self.pds.reinitialize_database()
        else:
            self.logger.info("Found existing database")

    def bootstrap_node(self):
        self.create_database_if_not_exist()

    def __repr__(self):
        return "<CLI>"


def main():
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
