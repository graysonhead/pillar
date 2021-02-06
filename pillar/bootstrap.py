from argparse import Namespace
from pillar.config import PillardConfig
from pillar.db import PillarDataStore
from pillar.IPRPC.cid_messenger import CIDMessenger
from pillar.keymanager import KeyManager, KeyManagerCommandQueueMixIn,\
    PillarKeyType
from pillar.identity import PrimaryIdentityMixIn, Primary
from pillar.ipfs import IPFSWorker
from pillar.multiproc import MixedClass
from pathlib import Path
import os
import sys
import logging


class BootstrapInterface(KeyManagerCommandQueueMixIn,
                         PrimaryIdentityMixIn,
                         metaclass=MixedClass):
    pass


class Bootstrapper:

    def __init__(self,
                 args: Namespace,
                 ):
        self.logger = logging.getLogger(f"<{self.__class__.__name__}>")
        self.planned_steps = []
        self.args = args
        self.pds = None
        self.key_manager = None
        self.config_path = None
        self.config = None
        self.user_key_name = self.args.user_name or self.user_name_prompt()
        self.user_key_email = self.args.email or self.email_prompt()
        self.defaults = self.args.defaults
        self.interface = BootstrapInterface()
        self.bootstrap()

    def bootstrap(self):
        self.config_path, self.config = self.bootstrap_config_file_pre()
        self.pds = self.bootstrap_pds_pre()
        print("We will take the follwing actions:\n")
        print("======================")
        for step in self.planned_steps:
            print(step)
            print("======================")
        continue_prompt = input("Take these actions? yes/[no]")
        if continue_prompt.lower() in 'yes':
            self.bootstrap_pre()

            self.bootstrap_execute()

            self.bootstrap_post()
        else:
            sys.exit(1)

    def bootstrap_pre(self):

        self.ipfs_worker = IPFSWorker("bootstrap")
        self.ipfs_worker.start()

        self.cid_messenger = CIDMessenger(
            PillarKeyType.USER_PRIMARY_KEY, self.config)
        self.cid_messenger.start()

        self.key_manager = self.bootstrap_keymanager_pre()
        self.key_manager.start()

        self.primary_worker = Primary(self.config)
        self.primary_worker.start()

    def bootstrap_post(self):
        self.key_manager.exit()
        self.cid_messenger.exit()
        self.ipfs_worker.exit()
        self.primary_worker.exit()

    def bootstrap_pds_pre(self) -> PillarDataStore:
        pds = PillarDataStore(self.config)
        if pds.database_exists():
            if not self.args.purge:
                raise FileExistsError(
                    f"Database {self.config.get_value('db_path')} already "
                    f"exists. Run with --purge to re-initialize "
                    f"it")
            step = f"Delete and reinitialize database " \
                f"{self.config.get_value('db_path')}"
        else:
            step = f"Create and initialize database " \
                f"{self.config.get_value('db_path')}"
        self.planned_steps.append(step)
        return pds

    def bootstrap_pds_exec(self):
        print("Creating database")
        self.pds.create_database(purge=self.args.purge)
        print("Database created")

    def user_name_prompt(self):
        i = 3
        while i > 0:
            i -= 1
            user_name = input("Please type your full name for key "
                              "generation: ")
            if user_name == '':
                print("Name field cannot be blank")
            else:
                return user_name
        exit(1)

    def email_prompt(self):
        i = 3
        while i > 0:
            i -= 1
            email = input("Please type your email address for key "
                          "generation: ")
            if email == '':
                print("Email field cannot be blank")
            else:
                return email
        exit(1)

    def bootstrap_keymanager_pre(self) -> KeyManager:
        keymanager = KeyManager(self.config)
        if keymanager.node_subkey is not None:
            if not self.args.purge:
                raise FileExistsError(
                    f"We found existing keys in the config_directory ("
                    f"{self.config.get_value('config_directory')}),"
                )
            else:
                pass

        return keymanager

    def bootstrap_keymanager_exec(self):
        self.interface.primary_identity.bootstrap(self.user_key_name,
                                                  self.user_key_email)

    def bootstrap_execute(self):
        self.bootstrap_config_file_exec()
        self.bootstrap_pds_exec()
        self.bootstrap_keymanager_exec()

    def bootstrap_config_file_exec(self):
        print(f"Writing config file {self.config_path}")
        self.config.generate_config(self.config_path)
        print("Wrote config file")

    def bootstrap_config_file_pre(self) -> tuple:
        if self.args.config:
            config_location = Path(self.args.config).expanduser()
        else:
            config_location = "/etc/pillar/pillar.yaml"
        config_path = Path(config_location)
        if config_path.exists():
            if self.args.purge:
                os.remove(str(config_path))
            else:
                raise FileExistsError(
                    f"The config file {str(config_path)}, already exists, run "
                    f"again with --purge to delete it.")
        config_obj = PillardConfig()
        print("The following questions will generate the config file for "
              "pillar, you can press enter to accept the defaults (shown "
              "in brackets.)")
        if not self.defaults:
            for option in config_obj.options:
                description = option.description or option.attribute
                opt_response = input(f"{description} "
                                     f"[{option.default_value}]: ")
                if opt_response:
                    # Set the type of the input to a valid one
                    opt_response = option.valid_types[0](opt_response)
                    config_obj.set_value(option.attribute, opt_response)
        step = f"We will create a config file at {str(config_path)} with " \
            f"contents: \n{config_obj.generate_yaml()}\n"
        self.planned_steps.append(step)
        return str(config_path), config_obj
