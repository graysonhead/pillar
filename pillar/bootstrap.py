from argparse import Namespace
from pillar.config import Config
from pillar.db import PillarDataStore
from pathlib import Path
import os
import sys


class Bootstrapper:

    def __init__(self,
                 args: Namespace,
                 ):
        self.planned_steps = []
        self.args = args
        self.pds = None
        self.key_manager = None
        self.config_path = None
        self.config = None

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

    def bootstrap_pds_pre(self) -> PillarDataStore:
        pds = PillarDataStore(self.config)
        if pds.database_exists():
            if not self.args.purge:
                raise FileExistsError(
                    f"Database {self.config.get_value('db_uri')} already "
                    f"exists. Run with --purge to re-initialize "
                    f"it")
            step = f"Delete and reinitialize database " \
                f"{self.config.get_value('db_uri')}"
        else:
            step = f"Create and initialize database " \
                f"{self.config.get_value('db_uri')}"
        self.planned_steps.append(step)
        return pds

    def bootstrap_pds_exec(self):
        print("Creating database")
        self.pds.create_database(purge=self.args.purge)
        print("Database created")

    def bootstrap_execute(self):
        self.bootstrap_config_file_exec()
        self.bootstrap_pds_exec()

    def bootstrap_config_file_exec(self):
        print(f"Writing config file {self.config_path}")
        self.config.generate_config(self.config_path)
        print("Wrote config file")

    def bootstrap_config_file_pre(self) -> tuple:
        if self.args.config:
            config_location = self.args.config
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
