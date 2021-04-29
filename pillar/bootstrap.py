from argparse import Namespace
from pillar.config import PillardConfig
from pillar.db import PillarDataStore
from pillar.keymanager import KeyManager, KeyManagerCommandQueueMixIn, \
    KeyManagerInstanceData
from pillar.multiproc import MixedClass
from pillar.IPRPC.cid_messenger import CIDMessengerMixIn
from pathlib import Path
from pillar.daemon import PillarDaemon
import os
import sys
import logging


class BootstrapInterface(KeyManagerCommandQueueMixIn,
                         CIDMessengerMixIn,
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
        self.interface = None
        self.key_steps()
        self.defaults = self.args.defaults
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
        pass

    def bootstrap_post(self):
        self.daemon.stop()

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

    def key_steps(self):
        if self.args.register:
            self.registrar_fingerprint = self.args.register
            self.register_node = True
        else:
            if self.args.email or self.args.user_name:
                self.register_node = False
            else:
                self.register_node = self.register_prompt()
                if self.register_node:
                    self.registrar_fingerprint = \
                        self.registrar_fingerprint_prompt()

        if self.register_node:
            step = f"Register this node using registrar fingerprint "\
                   f"{self.registrar_fingerprint}."
        else:
            self.user_key_name = self.args.user_name or self.user_name_prompt()
            self.user_key_email = self.args.email or self.email_prompt()
            step = f"Generate a new user primary key for {self.user_key_name}."
        self.planned_steps.append(step)

    def ask_three_times(self, prompt: str):
        i = 3
        while i > 0:
            i -= 1
            out = input(prompt)
            if out == '':
                print("Field cannot be blank")
            else:
                return out
        exit(1)

    def registrar_fingerprint_prompt(self):
        return self.ask_three_times("Input the fingerprint cid for your "
                                    "registrar node: ")

    def user_name_prompt(self):
        return self.ask_three_times("Please type your full name for key "
                                    "generation: ")

    def email_prompt(self):
        return self.ask_three_times("Please type email address for key "
                                    "generation: ")

    def register_prompt(self):
        prompt = input(
            "Are you registering this node with "
            "an existing pillar user? yes/[no]")
        if prompt.lower() in 'yes' and prompt != '':
            return True
        else:
            return False

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

    def bootstrap_user_exec(self):
        self.daemon = PillarDaemon(self.config, bootstrap=True)
        self.command_queue, self.output_queue = self.daemon.get_queues()
        self.daemon.start()
        self.interface = BootstrapInterface(str(self),
                                            command_queue=self.command_queue,
                                            output_queue=self.output_queue)
        self.logger.info("Generating User Primary key.")
        self.interface.\
            key_manager.generate_user_primary_key(
                self.user_key_name,
                self.user_key_email
            )

        self.interface.key_manager.generate_local_node_subkey()

        kmi = KeyManagerInstanceData(self.command_queue, self.output_queue)
        fc_message = self.interface.key_manager.create_fingerprint_message()

        print(fc_message)
        kmi.fingerprint_cid = self.interface.cid_messenger.\
            add_unencrypted_message_to_ipfs(fc_message)

        kmi.pds_save()
        self.logger.info("Bootstrap User complete.")

    def bootstrap_execute(self):
        self.bootstrap_config_file_exec()
        self.bootstrap_pds_exec()
        if self.register_node:
            print("Node registration not implemented")
            exit(1)
        else:
            self.bootstrap_user_exec()

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
