from pillar.config import PillardConfig
from argparse import Namespace
import logging
from pillar.identity import NodeIdentityMixIn
from pillar.bootstrap import Bootstrapper
from pillar.daemon import PillarDaemon
from pillar.keymanager import KeyManager, PillarKeyType
from pillar.db import PillarDataStore, PillarDBWorker
from pillar.multiproc import PillarThreadInterface
from pillar.IPRPC.cid_messenger import CIDMessenger
from pillar.ipfs import IPFSWorker
from pathlib import Path
import sys
import argparse


class CLIInterface(NodeIdentityMixIn, metaclass=MixedClass):
    pass


class CLI:

    def __init__(self, args: list):
        self.logger = logging.getLogger(self.__repr__())
        self.args = self.parse_args(args)
        self.interface = CLIInterface()

        if self.args.verb:
            logging.basicConfig(level=getattr(logging, self.args.verb))
            if self.args.verb == "DEBUG":
                PillarThreadInterface.debug = True
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
        elif self.args.sub_command == 'identity':

            key_manager = KeyManager(self.config)
            key_manager.start()

            ipfs_worker_instance = IPFSWorker(str(self))
            ipfs_worker_instance.start()
            cid_messenger_instance = CIDMessenger(
                PillarKeyType.NODE_SUBKEY,
                self.config)
            cid_messenger_instance.start()
            db_worker_instance = PillarDBWorker(self.config)
            db_worker_instance.start()

            pds = PillarDataStore(self.config)
            node = Node.get_local_instance(self.config, pds)
            node.start()
            if self.args.identity_command == 'create_invitation':
                print(self.interface.node_identity.create_invitation(
                    self.args.peer_fingerprint_cid))
            elif self.args.identity_command == 'fingerprint_cid':
                print(self.interface.node_identity.get_fingerprint_cid())
            elif self.args.identity_command == 'accept_invitation':
                self.interface.node_identity.receive_invitation_by_cid(
                    self.args.invitation_cid)
            daemon.exit()
        else:
            print("No subcommand provided")
            sys.exit(1)
        key_manager.exit()
        db_worker_instance.exit()
        cid_messenger_instance.exit()
        ipfs_worker_instance.exit()
        print("that's all?")

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
