from ..config import Config
from ..keymanager import EncryptionHelper
from ..ipfs import IPFSMixIn, IPFSWorker
from ..multiproc import PillarThreadMixIn, PillarThreadMethodsRegister,\
    PillarWorkerThread, MixedClass
from .messages import IPRPCRegistry, IPRPCMessage
import pgpy
import logging
import os
import asyncio
import multiprocessing as mp

cid_messenger_register = PillarThreadMethodsRegister()


class CIDMessengerInterface(IPFSMixIn, metaclass=MixedClass):
    pass


class CIDMessenger(PillarWorkerThread):
    command_queue = mp.Queue()
    output_queue = mp.Queue()
    shutdown_callback = mp.Event()
    methods_register = cid_messenger_register

    def __init__(self,
                 encryption_helper: EncryptionHelper,
                 config: Config):
        self.logger = logging.getLogger('<CIDMessenger>')
        self.logger.info("Starting CIDMessenger")
        self.encryption_helper = encryption_helper
        self.config = config
        self.interface = CIDMessengerInterface()
        super().__init__()

    def pre_run(self):
        self.ipfs_worker_instance = IPFSWorker(str(self))
        self.ipfs_worker_instance.start()

    def shutdown_routine(self):
        self.ipfs_worker_instance.exit()

    @cid_messenger_register.register_method
    def get_and_decrypt_message_from_cid(self, cid: str, verify: bool = True):
        self.logger.info(f'Retrieving encrypted message: {cid}')
        encrypted_message = self._get_cid_contents(cid)
        message = self.encryption_helper.\
            decrypt_and_verify_encrypted_message(
                encrypted_message, verify=verify)
        message_contents = pgpy.PGPMessage.from_blob(str(message))
        return IPRPCRegistry.deserialize_from_json(message_contents.message)

    @cid_messenger_register.register_method
    def get_unencrypted_message_from_cid(self, cid: str):
        self.logger.info(f'Retrieving unencrypted message: {cid}')
        message = self._get_cid_contents(cid)
        return IPRPCRegistry.deserialize_from_json(message)

    def _get_cid_contents(self, cid: str):
        self.interface.ipfs.get_file(
            cid, dstdir=self.config.get_value('ipfs_directory'))
        with open(os.path.join(
                self.config.get_value('ipfs_directory'), cid)) as f:
            return f.read()

    @cid_messenger_register.register_method
    def add_encrypted_message_to_ipfs_for_peer(self,
                                               message: IPRPCMessage,
                                               peer_fingerprint: str):
        serialized_message = message.serialize_to_json()
        encrypted_message = self.encryption_helper.\
            sign_and_encrypt_string_to_peer_fingerprint(
                serialized_message,
                peer_fingerprint)

        data = self.interface.ipfs.add_str(str(encrypted_message))
        self.logger.info(f"Created new encrypted message: {data['Hash']}")
        return data['Hash']

    @cid_messenger_register.register_method
    def add_unencrypted_message_to_ipfs(self,
                                        message: IPRPCMessage):
        serialized_message = message.serialize_to_json()
        data = self.interface.ipfs.add_str(str(serialized_message))
        self.logger.info(f"Created new unencrypted message: {data['Hash']}")
        return data['Hash']


class CIDMessengerMixIn(PillarThreadMixIn):
    queue_thread_class = CIDMessenger
    interface_name = "cid_messenger"
