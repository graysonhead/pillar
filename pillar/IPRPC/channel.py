import aioipfs
import asyncio
import logging
from enum import Enum
from urllib.parse import unquote
from .messages import IPRPCMessage, \
    PeeringHello, \
    PeeringHelloResponse, \
    IPRPCRegistry, \
    PeeringKeepalive
# from queue import Queue
# from threading import Thread
from multiprocessing import Process, Pipe
import time


class CallChannel:

    def __init__(self,
                 ipfs_queue_id: str,
                 aioipfs_instance: aioipfs.AsyncIPFS):
        self.queue_id = ipfs_queue_id
        self.ipfs = aioipfs_instance
        self.logger = logging.getLogger(self.__repr__())

    async def send_message(self, message: str):
        async with self.ipfs as ipfs:
            await ipfs.pubsub.pub(self.queue_id,
                                  message)
            self.logger.info(f"Sent message: {message}")

    async def send_message_from_pipe(self, pipe: Pipe):
        message = pipe.recv()
        await self.send_message(message)

    async def retrieve_messages_to_pipe(self, pipe: Pipe):
        async with self.ipfs as ipfs:
            async for message in ipfs.pubsub.sub(self.queue_id):
                serialized_message = unquote(message['data'].decode('utf-8'))
                self.logger.info(f"Got message: {serialized_message}")
                pipe.send(serialized_message)

    async def get_messages(self):
        async with self.ipfs as ipfs:
            async for message in ipfs.pubsub.sub(self.queue_id):
                self.logger.info(f"Got message: "
                                 f"{message}")
                yield unquote(message['data'].decode('utf-8'))

    def __repr__(self):
        return f"<CallChannel: queue_id={self.queue_id}>"


class PeeringStatus(Enum):
    IDLE = 1
    ESTABLISHING = 2
    ESTABLISHED = 3


class PeerChannel:

    def __init__(self,
                 peer_id: str,
                 rx_queue_id: str,
                 tx_queue_id: str,
                 keepalive_interval: int = 10,
                 keepalive_timeout: int = 20):
        self.our_id = peer_id
        self.peer_id = None
        self.ready = False
        self.keepalive_interval = keepalive_interval
        self.keepalive_timeout = keepalive_timeout
        self.rx_queue_id = rx_queue_id
        self.tx_queue_id = tx_queue_id
        self.logger = logging.getLogger(self.__repr__())
        # Set up Transmit Thread
        self.tx_pipe, tx_thread_pipe = Pipe()
        tx_loop = asyncio.new_event_loop()
        self.tx_thread = Process(target=self._create_tx_callchannel,
                                 args=(tx_loop, tx_thread_pipe))
        self.tx_thread.start()
        self.logger.info(f"Spawned tx_thread {self.tx_thread}")
        # Set up receive thread
        self.rx_pipe, rx_thread_pipe = Pipe()
        rx_loop = asyncio.new_event_loop()
        self.rx_thread = Process(target=self._create_rx_callchannel,
                                 args=(rx_loop, rx_thread_pipe))
        self.rx_thread.start()
        self.logger.info(f"Spawned rx_thread {self.tx_thread}")
        self.status = PeeringStatus.IDLE
        # self.establish_connection()

    def establish_connection(self, timeout=30):
        self.logger.info("Attempting to establish contact with remote peer")

        self._change_peering_status(PeeringStatus.ESTABLISHING)
        timeout = time.time() + timeout
        while True:
            self.send_call(PeeringHello(initiator_id=self.our_id))
            if self.rx_pipe.poll(1):
                rx_call = self.receive_call()
                if type(rx_call) == PeeringHelloResponse:
                    self.ready = True
                    self._change_peering_status(PeeringStatus.ESTABLISHED)
                    self.peer_id == rx_call.responder_id
                    self.logger.info("Channel established, "
                                     "processing messages")
                    self.process_messages()
                elif type(rx_call) == PeeringHello:
                    self.send_call(
                        PeeringHelloResponse(responder_id=self.our_id))
                    self.ready = True
                    self._change_peering_status(PeeringStatus.ESTABLISHED)
                    self.peer_id == rx_call.initiator_id
                    self.logger.info("Channel established,"
                                     "processing messages")
                    self.process_messages()
            if time.time() > timeout:
                self.logger.error("Failed to establish connection with peer, "
                                  "timout exceeded.")
                self._change_peering_status(PeeringStatus.IDLE)
                break
            time.sleep(5)

    def process_messages(self):
        timeout = time.time() + self.keepalive_timeout
        keepalive = time.time() + self.keepalive_interval
        while True:
            if time.time() > timeout:
                self._change_peering_status(PeeringStatus.IDLE)
                self.establish_connection()
            if time.time() > keepalive:
                self.send_call(PeeringKeepalive())
                keepalive = time.time() + self.keepalive_interval
            if self.rx_pipe.poll(1):
                rx_call = self.receive_call()
                if type(rx_call) == PeeringKeepalive:
                    self.logger.info("Got keepalive message, renewing timeout")
                    timeout = time.time() + self.keepalive_timeout

    def _change_peering_status(self, new_status: PeeringStatus):
        self.logger.info(f"Peering status change from {self.status} to "
                         f"{new_status}")
        self.status = new_status

    def _create_rx_callchannel(self, loop, rx_thread_pipe):
        asyncio.set_event_loop(loop)
        ipfs_instance = aioipfs.AsyncIPFS()
        channel = CallChannel(self.rx_queue_id, ipfs_instance)
        while True:
            loop.run_until_complete(
                channel.retrieve_messages_to_pipe(rx_thread_pipe))

    def _create_tx_callchannel(self, loop, pipe: Pipe):
        asyncio.set_event_loop(loop)
        ipfs_instance = aioipfs.AsyncIPFS()
        channel = CallChannel(self.tx_queue_id, ipfs_instance)
        while True:
            loop.run_until_complete(channel.send_message_from_pipe(pipe))

    def _stop_threads(self):
        self.tx_pipe.close()
        self.rx_pipe.close()
        self.rx_thread.terminate()
        self.rx_thread.join()
        self.tx_thread.terminate()
        self.tx_thread.join()

    def send_call(self, call: IPRPCMessage):
        # Encryption happens here?
        serialized_message = call.serialize_to_json()
        self.send_message(serialized_message)

    def send_message(self, message: str):
        self.tx_pipe.send(message)

    def receive_message(self):
        return self.rx_pipe.recv()

    def receive_call(self):
        serialized_message = self.receive_message()
        return IPRPCRegistry.deserialize_from_json(serialized_message)

    def __del__(self):
        # Viciously Murder children on garbage collection
        self._stop_threads()

    def __repr__(self):
        return f"<PeerChannel: {self.our_id}>"
