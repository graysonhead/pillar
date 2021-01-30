from argparse import Namespace
from pillar.config import Config
from pillar.db import PillarDataStore
from pillar.keymanager import KeyManager, KeyManagerCommandQueueMixIn
from pillar.ipfs import IPFSWorker
from pathlib import Path
import os
import sys


class Bootstrapper(KeyManagerCommandQueueMixIn):

    def __init__(self,
                 args: Namespace,
                 ):
        self.planned_steps = []
        self.args = args
        self.pds = None
        self.key_manager = None
        self.config_path = None
        self.config = None
        self.user_key_name = None
        self.user_key_email = None
        super().__init__()

    def bootstrap(self):
        self.bootstrap_pre()
        print("We will take the follwing actions:\n")
        print("======================")
        for step in self.planned_steps:
            print(step)
            print("======================")
        continue_prompt = input("Take these actions? yes/[no]")
        if continue_prompt.lower() in 'yes':
            self.bootstrap_execute()
        else:
            sys.exit(1)

    def bootstrap_pre(self):
        self.config_path, self.config = self.bootstrap_config_file_pre()
        self.pds = self.bootstrap_pds_pre()
        self.key_manager = self.bootstrap_keymanager_pre()

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

    def bootstrap_keymanager_pre(self):
        keymanager = KeyManager(self.config, self.pds, db_import=False)
        if keymanager.node_subkey is not None:
            if not self.args.purge:
                raise FileExistsError(
                    f"We found existing keys in the config_directory ("
                    f"{self.config.get_value('config_directory')}),"
                )
            else:
                pass
        user_name = input("Please type your full name for key generation: ")
        if not user_name:
            print("Name field cannot be blank")
            sys.exit(1)
        else:
            self.user_key_name = user_name
        user_email = input(
            "Please type your e-mail address for key generation: "
        )
        if not user_email:
            print("Email field cannot be blank")
        else:
            self.user_key_email = user_email

        return keymanager

    def bootstrap_keymanager_exec(self):
        from .identity import Primary
        
        self.ipfs_worker = IPFSWorker(f"{self.__class__.__name__}")
        self.ipfs_worker.start()
        self.key_manager.start()

        self.primary_worker = Primary(self.config)
        self.primary_worker.start()

        self.primary_identity.bootstrap(self.user_key_name, self.user_key_email)
        print("heloooo!!!!!!")

        self.primary_worker.exit()
        self.ipfs_worker.exit()
        self.key_manager.exit()

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
        config_obj = Config()
        print("The following questions will generate the config file for "
              "pillar, you can press enter to accept the defaults (shown "
              "in brackets.)")
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
