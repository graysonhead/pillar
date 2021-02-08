import asyncio
import logging
from enum import Enum
from urllib.parse import unquote
from .messages import IPRPCMessage,\
    PeeringHello, \
    PeeringHelloResponse, \
    IPRPCRegistry, \
    PeeringKeepalive
from ..encryption_helper import EncryptionHelper
from ..ipfs import IPFSClient
from multiprocessing import Process, Pipe
from ..async_untils import handler_loop
import time
import pgpy
import hashlib
from datetime import datetime, timedelta


class PeeringStatus(Enum):
    IDLE = 1
    ESTABLISHING = 2
    ESTABLISHED = 3


def generate_queue_id(*fingerprints,
                      preshared_key: str = '',
                      datetime: datetime = datetime.utcnow()) -> str:
    """
    This function takes a set of fingerprints, sorts the strings alphabetically
    and then hashes the result along with the datetime and an optionally
    pre-shared-key. The result will change every hour.

    Given the same input values on both sides of a channel, the generated
    channel ID will be the same, allowing the nodes to connect with each other.

    :param fingerprints:
        The string representation of a key fingerprint
    :param preshared_key:
        An optional pre-shared-key
    :param datetime:
        A Datetime object
    :return:
        A hashed string generated from the input values.
    """
    fingerprint_list = []
    for fingerprint in fingerprints:
        fingerprint_list.append(fingerprint)
    fingerprint_list.sort()
    string = '-'.join(fingerprint_list)
    string = string + f"{datetime.year}-" \
        f"{datetime.month}-" \
        f"{datetime.day}-" \
        f"{datetime.hour}"
    chan = string + preshared_key
    chan_hash = hashlib.sha256(chan.encode('utf-8'))
    return chan_hash.hexdigest()


class IPRPCChannel(Process):
    """
    An IPRPC (InterPlanetary Remote Procedure Call) channel is the base unit
    of communication in pillar. It allows two nodes to pass IPRPCMessages
    between each other using IPFS pubsub queues. It generates random channel
    IDs based on the peer fingerprints, time, and an optional pre-shared-key.

    The queue IDs will rotate every hour, and the channel listens on both
    the previous hour and next hours ID so no messages should be lost during
    the transition.

    This class is designed to be run as a subprocess, as such it is started
    with the .start() method, which calls the .run() method in a subprocess.
    Messages are received from and passed to this thread using the pipe
    endpoints returned by the .get_pipe_endpoints() method.
    """

    def __init__(self,
                 id: str,
                 peer_fingerprint: str = None,
                 encryption_helper: EncryptionHelper = None,
                 ipfs_instance: IPFSClient = None,
                 keepalive_send_interval: int = 30,
                 keepalive_timeout_interval: int = 60,
                 pre_shared_key: str = ''):
        self.id = id
        self.peer_id = peer_fingerprint
        self.pre_shared_key = pre_shared_key
        self.queues = []
        self.encryption_helper = encryption_helper
        self.ipfs = ipfs_instance or IPFSClient()
        self.our_ipfs_peer_id = None
        self.tx_input, self.tx_output = Pipe()
        self.rx_input, self.rx_output = Pipe()
        self.status = PeeringStatus.IDLE
        self.logger = logging.getLogger(self.__repr__())
        self.keepalive_send_interval = keepalive_send_interval
        self.keepalive_timeout_interval = keepalive_timeout_interval
        self.timeout = None
        self.keepalive_send_timeout = None
        self._establish_and_rotate_queues()
        super().__init__()
        self.logger.info(
            f"Spawned channel between {self.id} and {self.peer_id}")
        self.logger.info(
            f"Initial channel window: {self.queues}"
        )

    def get_pipe_endpoints(self):
        """
        Returns the endpoints that allow messages to be sent and received
        from this thread.
        :return:
            tx_pipe, rx_pipe
        """
        return self.tx_input, self.rx_output

    def run(self) -> None:
        """
        This method should not be called directly, .start() will start a
        subprocess thread where this method will be called.
        :return:
        """
        while True:
            self.timeout = time.time() + self.keepalive_timeout_interval
            self.keepalive_send_timeout = time.time() + \
                self.keepalive_send_interval
            rx_workers = []
            asyncio.ensure_future(handler_loop(
                self._handle_establish_connection, sleep=5)
            )
            rx_workers.append(asyncio.ensure_future(
                handler_loop(
                    self._handle_messages_current_window,
                    sleep=.01
                )
            ))
            rx_workers.append(asyncio.ensure_future(
                handler_loop(
                    self._handle_messages_previous_window,
                    sleep=.01
                )
            ))
            rx_workers.append(asyncio.ensure_future(
                handler_loop(
                    self._handle_messages_next_window,
                    sleep=.01
                )
            ))
            asyncio.ensure_future(
                handler_loop(
                    self._handle_tx_queue_messages,
                    sleep=.01
                )
            )
            asyncio.ensure_future(
                handler_loop(
                    self._handle_keepalive,
                    sleep=5,
                )
            )
            asyncio.ensure_future(
                handler_loop(
                    self._handle_timeout,
                    sleep=5,
                )
            )
            asyncio.ensure_future(handler_loop(
                self._async_rotate_queues_wrapper,
                sleep=5
            ))
            loop = asyncio.get_event_loop()
            loop.run_forever()
            print(f"Cancelling rx workers: {rx_workers}")
            for rx_worker in rx_workers:
                rx_worker.cancel()

    def _change_peering_status(self, new_status: PeeringStatus):
        if self.status != new_status:
            self.logger.info(f"Peering status change from {self.status} to "
                             f"{new_status}")
            self.status = new_status

    async def _handle_establish_connection(self) -> None:
        """
        Sends a PeeringHello message to wake up the other side of the
        connection.
        """
        if not self.status == PeeringStatus.ESTABLISHED:
            self._change_peering_status(PeeringStatus.ESTABLISHING)
            await self._send_message(PeeringHello(initiator_id=self.id))

    async def _handle_tx_queue_messages(self) -> None:
        """
        If state == ESTABLISHED, this will pull messages from the tx queue pipe
        and send them to the other peer.
        """
        if self.status == PeeringStatus.ESTABLISHED:
            if self.tx_output.poll():
                message = self.tx_output.recv()
                await self._send_message(message)

    async def _handle_timeout(self) -> None:
        if time.time() > self.timeout:
            if not self.status == PeeringStatus.ESTABLISHING:
                self._change_peering_status(PeeringStatus.IDLE)

    async def _async_rotate_queues_wrapper(self) -> None:
        """
        If the _establish_and_rotate_queues() returns true, this resets the
        event loop and stops all worker asyncio events so they don't wait
        for messages on retired channels.
        """
        loop = asyncio.get_event_loop()
        result = self._establish_and_rotate_queues()
        if result:
            self.logger.info("Event loop reset")
            loop.stop()

    def _establish_and_rotate_queues(self) -> bool:
        """
        Handles rotating the sliding queue_id window.
        :return:
            True on window change
            False on no change
        """
        previous_queue_id = self._get_queue_id(time_delta=timedelta(hours=-1))
        current_queue_id = self._get_queue_id()
        next_queue_id = self._get_queue_id(time_delta=timedelta(hours=1))
        current_list = [previous_queue_id, current_queue_id, next_queue_id]
        if not self.queues:
            self.logger.info(f"Current Queues: {self.queues}")
            self.queues = current_list
            return True
        elif self.queues != current_list:
            self.logger.info(f"Window slide occured, Old Queues: {self.queues}"
                             f"New Queues: {current_list}")
            self.queues = current_list
            return True
        else:
            return False

    async def _handle_messages_previous_window(self) -> None:
        await self._handle_incoming_messages(self.queues[0])

    async def _handle_messages_next_window(self) -> None:
        await self._handle_incoming_messages(self.queues[2])

    async def _handle_messages_current_window(self) -> None:
        await self._handle_incoming_messages(self.queues[1])

    def _get_queue_id(self, time_delta=None):
        if time_delta:
            time = datetime.utcnow() + time_delta
        else:
            time = datetime.utcnow()
        return generate_queue_id(
            self.id,
            self.peer_id,
            preshared_key=self.pre_shared_key,
            datetime=time
        )

    async def _handle_incoming_messages(self, queue_id: str) -> None:
        """
        Handles messages received from the other peer.
        Some messages are needed by the class to establish a connection or keep
        it alive. All others are output over the rx pipe so they can be passed
        to other processes.
        :param queue_id:
            ID of the pubsub queue to handle messages on.
        """
        async for rx_message in self._get_message(queue_id):
            if type(rx_message) is PeeringHello:
                await self._send_message(
                    PeeringHelloResponse(responder_id=self.id)
                )
            elif type(rx_message) is PeeringHelloResponse:
                self.peer_id = rx_message.responder_id
                self._change_peering_status(PeeringStatus.ESTABLISHED)
            elif type(rx_message) is PeeringKeepalive:
                self.timeout = time.time() + \
                    self.keepalive_timeout_interval
            else:
                self.rx_input.send(rx_message)

    async def _handle_keepalive(self):
        if self.status == PeeringStatus.ESTABLISHED:
            if time.time() > self.keepalive_send_timeout:
                await self._send_message(PeeringKeepalive())
                self.keepalive_send_timeout = time.time() + \
                    self.keepalive_send_interval

    async def _set_our_ipfs_peer_id(self) -> None:
        """This sets self.our_ipfs_peer_id so we can ignore messages we sent"""
        id_info = await self.ipfs.get_id()
        self.our_ipfs_peer_id = id_info.get('ID')
        self.logger.info(f"Set our ipfs peer id to {self.our_ipfs_peer_id}")

    async def _send_message(self, call: IPRPCMessage):
        message = call.serialize_to_json()
        if self.encryption_helper:
            message = self.encryption_helper.\
                    sign_and_encrypt_string_to_peer_fingerprint(
                        message,
                        self.peer_id
                    )
        await self._send_ipfs(message)
        self.logger.info(f"Sent message: {call}")

    async def _send_ipfs(self, message: str) -> None:
        await self.ipfs.send_pubsub_message(self.queues[1], message)

    async def _get_from_ipfs(self, queue_id: str):
        if not self.our_ipfs_peer_id:
            await self._set_our_ipfs_peer_id()
        async for message in self.ipfs.get_pubsub_message(queue_id):
            if not message['from'].decode() == self.our_ipfs_peer_id:
                raw_message = unquote(message['data'].decode('utf-8'))
                yield raw_message

    async def _get_message(self, queue_id: str):
        async for message in self._get_from_ipfs(queue_id):
            if self.encryption_helper:
                try:
                    message = self._decrypt_message(message)
                except Exception as e:
                    self.logger.warning(f"Failed to decrypt message on"
                                        f" encrypted channel: {e}")
            try:
                message = IPRPCRegistry.deserialize_from_json(message)
                self.logger.info(f"Got message from peer: {message}")
                yield message
            except Exception as e:
                self.logger.warning(f"Failed to decodde message: {e}")

    def _decrypt_message(self, message: str):
        return self.encryption_helper.\
            decrypt_and_verify_encrypted_message(message)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}:" \
            f"peer_id={self.peer_id}>"


class ChannelManager:
    def __init__(self,
                 encryption_helper: EncryptionHelper,
                 local_fingerprint: str):
        self.logger = logging.getLogger('<ChannelManager>')
        self.local_fingerprint = local_fingerprint
        self.encryption_helper = encryption_helper
        self.channels = []
        self.pipes = {}

    def add_peer(self, public_key: pgpy.PGPKey):
        self.logger.info(f'Adding peer: {public_key.fingerprint}')
        for fingerprint, subkey in public_key.subkeys.items():
            channel = IPRPCChannel(
                    str(self.local_fingerprint),
                    str(subkey.fingerprint),
                    encryption_helper=self.encryption_helper)
            self.channels.append(channel)
            self.pipes.update({str(fingerprint):
                              channel.get_pipe_endpoints()})

    def start_channels(self):
        for channel in self.channels:
            channel.start()
