import argparse
from pillar.config import Config
from argparse import Namespace
import logging
from pillar.identity import Node
from pillar.bootstrap import Bootstrapper
from pillar.daemon import PillarDaemon
from pathlib import Path
import sys


class CLI:

    def __init__(self, args: list):
        self.logger = logging.getLogger(self.__repr__())
        self.args = self.parse_args(args)

        if self.args.verb:
            logging.basicConfig(level=getattr(logging, self.args.verb))
        if not self.args.sub_command == '' \
                                        'bootstrap':
            self.config = self.get_config(self.args.config)

    def run(self):
        if self.args.sub_command == 'bootstrap':
            self.bootstrap()
        elif self.args.sub_command == 'daemon':
            daemon = PillarDaemon(
                self.config,
                '/tmp/pillar.pid',
                stdout=sys.stdout,
                stderr=sys.stderr
            )
            daemon.start()
        elif self.args.sub_command == 'identity':
            nodes = Node.load_all_from_db(
                self.pds,
                init_args=[self.key_manager, self.config]
            )
            if self.args.identity_command == 'create_invitation':
                # TODO
                pass
            elif self.args.identity_command == 'fingerprint_cid':
                # TODO
                pass
            elif self.args.identity_command == 'accept_invitation':
                # TODO
                pass
            elif self.args.identity_command == 'show_fingerprints':
                print("Local Fingerprints:")
                print(f"Node: {nodes[0].fingerprint}")
                print(f"Peers: {self.key_manager.keyring.fingerprints()}")
        else:
            print("No subcommand provided")
            sys.exit(1)

    def bootstrap(self):
        bootstrap = Bootstrapper(
            self.args
        )
        bootstrap.bootstrap()

    def parse_args(self, args: list) -> Namespace:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="sub_command")
        bootstrap = subparsers.add_parser("bootstrap",
                                          help="Bootstrap a pillar node",
                                          )
        subparsers.add_parser("daemon",
                              help="Run pillar daemon")
        key = subparsers.add_parser("identity",
                                    help="Manage identities")
        keyparsers = key.add_subparsers(dest="identity_command")
        keyparsers.add_parser("fingerprint_cid",
                              help="Get fingerprint cid")
        create_invitation_parser = keyparsers.add_parser(
            "create_invitation",
            help="Create an invitation message for other users to accept.")
        create_invitation_parser.add_argument("peer_fingerprint_cid",
                                              help="Fingerprint CID of "
                                                   "invited peer.")
        accept_invitation = keyparsers.add_parser(
            "accept_invitation",
            help="Accept the invitation of another user")
        accept_invitation.add_argument("invitation_cid",
                                       help="Accept a generated invitation")
        keyparsers.add_parser("show_fingerprints",
                              help="List all key fingerprints")
        bootstrap.add_argument("--purge",
                               help="Removes and re-creates databases and"
                                    " config files.",
                               action='store_true')
        parser.add_argument("--config",
                            default='~/.pillar/pillar.yaml')
        parser.add_argument("--verb",
                            default="WARNING",
                            choices=["INFO", "DEBUG", "WARNING"])
        return parser.parse_args(args)

    def get_config(self, config_path: str) -> Config:
        path = Path(config_path).expanduser()
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
