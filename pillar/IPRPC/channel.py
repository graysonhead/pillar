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
from multiprocessing import Process, Pipe
import time


class PeeringStatus(Enum):
    IDLE = 1
    ESTABLISHING = 2
    ESTABLISHED = 3


class IPRPCChannel(Process):

    def __init__(self,
                 id: str,
                 ipfs_queue_id: str,
                 aioipfs_instance: aioipfs.AsyncIPFS,
                 keepalive_send_interval: int = 30,
                 keepalive_timeout_interval: int = 60):
        self.id = id
        self.queue_id = ipfs_queue_id
        self.peer_id = None
        self.ipfs = aioipfs_instance
        self.our_ipfs_peer_id = None
        self.tx_input, self.tx_output = Pipe()
        self.rx_input, self.rx_output = Pipe()
        self.status = PeeringStatus.IDLE
        self.keepalive_send_interval = keepalive_send_interval
        self.keepalive_timeout_interval = keepalive_timeout_interval
        self.timeout = None
        super().__init__()
        self.logger = logging.getLogger(f"<IPRPCChannel:{self.queue_id}>")

    def run(self) -> None:
        asyncio.ensure_future(self._handle_establish_connection())
        asyncio.ensure_future(self._handle_incoming_messages())
        asyncio.ensure_future(self._handle_keepalive())
        asyncio.ensure_future(self._handle_timeout())
        loop = asyncio.get_event_loop()
        loop.run_forever()

    def _change_peering_status(self, new_status: PeeringStatus):
        self.logger.info(f"Peering status change from {self.status} to "
                         f"{new_status}")
        self.status = new_status

    async def _handle_establish_connection(self):
        while True:
            if not self.status == PeeringStatus.ESTABLISHED:
                self._change_peering_status(PeeringStatus.ESTABLISHING)
                await self._send_message(PeeringHello(initiator_id=self.id))
            await asyncio.sleep(5)

    async def _handle_timeout(self):
        while True:
            if time.time() > self.timeout:
                if not self.status == PeeringStatus.ESTABLISHING:
                    self._change_peering_status(PeeringStatus.IDLE)
            await asyncio.sleep(5)

    async def _handle_incoming_messages(self):
        self.timeout = time.time() + self.keepalive_timeout_interval
        while True:
            async for rx_message in self._get_message():
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
                    self.logger.info(f"Would have sent {rx_message} to queue")

    async def _handle_keepalive(self):
        keepalive_send_timeout = time.time() + self.keepalive_send_interval
        while True:
            if self.status == PeeringStatus.ESTABLISHED:
                if time.time() > keepalive_send_timeout:
                    await self._send_message(PeeringKeepalive())
                    keepalive_send_timeout = time.time() + \
                        self.keepalive_send_interval
            await asyncio.sleep(5)

    async def _set_our_ipfs_peer_id(self) -> None:
        """This sets self.our_ipfs_peer_id so we can ignore messages we sent"""
        id_info = await self.ipfs.core.id()
        self.our_ipfs_peer_id = id_info.get('ID')

    async def _send_message(self, call: IPRPCMessage):
        await self._send_ipfs(call.serialize_to_json())
        self.logger.info(f"Sent message: {call}")

    async def _send_ipfs(self, message: str) -> None:
        async with self.ipfs as ipfs:
            await ipfs.pubsub.pub(self.queue_id, message)
        self.logger.info(f"Sent raw message: {message}")

    async def _get_from_ipfs(self):
        if not self.our_ipfs_peer_id:
            await self._set_our_ipfs_peer_id()
            self.logger.info(f"Set our peer id to {self.our_ipfs_peer_id}")
        else:
            async with self.ipfs as ipfs:
                async for message in ipfs.pubsub.sub(self.queue_id):
                    if not message['from'].decode() == self.our_ipfs_peer_id:
                        raw_message = unquote(message['data'].decode('utf-8'))
                        self.logger.info(f"Got raw message: {message}")
                        yield raw_message

    async def _get_message(self):
        async for message in self._get_from_ipfs():
            try:
                yield IPRPCRegistry.deserialize_from_json(message)
            except Exception as e:
                self.logger.warning(f"Decoding failed on message: {e}")

    async def _close_aio_connection(self):
        await self.ipfs.close()

    def __del__(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._close_aio_connection())

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}:queue_id={self.queue_id}," \
            f"peer_id={self.peer_id}," \
            f"status={self.status.name}>"


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


class PeerChannel:

    def __init__(self,
                 peer_id: str,
                 rx_queue_id: str,
                 tx_queue_id: str,
                 keepalive_interval: int = 60,
                 keepalive_timeout: int = 120):
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
                    break
                elif type(rx_call) == PeeringHello:
                    self.send_call(
                        PeeringHelloResponse(responder_id=self.our_id))
                    self.ready = True
                    self._change_peering_status(PeeringStatus.ESTABLISHED)
                    self.peer_id == rx_call.initiator_id
                    self.logger.info("Channel established,"
                                     "processing messages")
                    break
            if time.time() > timeout:
                self.logger.error("Failed to establish connection with peer, "
                                  "timout exceeded.")
                self._change_peering_status(PeeringStatus.IDLE)
                break
            time.sleep(5)

    def idle_connection(self):
        self._change_peering_status(PeeringStatus.IDLE)
        self.ready = False

    def process_messages(self):
        timeout = time.time() + self.keepalive_timeout
        keepalive = time.time() + self.keepalive_interval
        while True:
            if not self.ready:
                self.establish_connection()
            else:
                if time.time() > timeout:
                    self.idle_connection()
                if time.time() > keepalive:
                    self.send_call(PeeringKeepalive())
                    keepalive = time.time() + self.keepalive_interval
                if self.rx_pipe.poll(1):
                    rx_call = self.receive_call()
                    if type(rx_call) == PeeringKeepalive:
                        self.logger.info("Got keepalive message, "
                                         "renewing timeout")
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
