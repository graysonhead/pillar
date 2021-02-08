import argparse
from pillar.config import PillardConfig
from argparse import Namespace
import logging
from pillar.identity import Node
from pillar.bootstrap import Bootstrapper
from pillar.daemon import PillarDaemon
from pillar.keymanager import KeyManager
from pillar.db import PillarDataStore
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
            Bootstrapper(self.args)
            exit(0)
        elif self.args.sub_command == 'daemon':
            daemon = PillarDaemon(
                self.config
            )
            daemon.start()
            daemon.start_housekeeping()
        elif self.args.sub_command == 'identity':
            pds = PillarDataStore(self.config)
            key_manager = KeyManager(self.config, pds)
            key_manager.start()

            node = Node.get_local_instance(self.config, pds)
            node.start()

            if self.args.identity_command == 'create_invitation':
                print(node.create_invitation(self.args.peer_fingerprint_cid))
            elif self.args.identity_command == 'fingerprint_cid':
                print(node.fingerprint_cid)
            elif self.args.identity_command == 'accept_invitation':
                node.receive_invitation_by_cid(self.args.invitation_cid)
            elif self.args.identity_command == 'show_fingerprints':
                print("Local Fingerprints:")
                print(f"Node: {node.fingerprint}")
                print(f"Peers: {self.key_manager.keyring.fingerprints()}")
        else:
            print("No subcommand provided")
            sys.exit(1)

    def parse_args(self, args: list) -> Namespace:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="sub_command")
        bootstrap = subparsers.add_parser("bootstrap",
                                          help="Bootstrap a pillar node",
                                          )
        bootstrap.add_argument("--defaults",
                               help="Accept all of pillar's default options",
                               action='store_true')
        bootstrap.add_argument("--user-name", help="Full name of the person "
                               "whose pillar user is being bootstrapped")

        bootstrap.add_argument("--email", help="Email address of the person "
                               "whose pillar user is being bootstrapped")

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

    def get_config(self, config_path: str) -> PillardConfig:
        path = Path(config_path).expanduser()
        self.logger.info(f"Loading config file from {config_path}")
        try:
            config = PillardConfig.load_from_yaml(str(path))
        except FileNotFoundError:
            config = PillardConfig()
            self.logger.info(f"Didn't find config file, created one at"
                             f" {config_path}")

        self.logger.info(f"Loaded options: {config.get_dict()}")
        return config

    def __repr__(self):
        return "<CLI>"
