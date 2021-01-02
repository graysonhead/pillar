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
        self.keepalive_send_timeout = None
        super().__init__()
        self.logger = logging.getLogger(f"<IPRPCChannel:{self.queue_id}>")

    def run(self) -> None:
        self.timeout = time.time() + self.keepalive_timeout_interval
        self.keepalive_send_timeout = time.time() + \
            self.keepalive_send_interval
        asyncio.ensure_future(self._handler_loop(
            self._handle_establish_connection, sleep=5))
        asyncio.ensure_future(
            self._handler_loop(self._handle_incoming_messages))
        asyncio.ensure_future(self._handler_loop(self._handle_keepalive,
                                                 sleep=5))
        asyncio.ensure_future(self._handler_loop(self._handle_timeout,
                                                 sleep=5))
        loop = asyncio.get_event_loop()
        loop.run_forever()

    def _change_peering_status(self, new_status: PeeringStatus):
        self.logger.info(f"Peering status change from {self.status} to "
                         f"{new_status}")
        self.status = new_status

    async def _handle_establish_connection(self):
        if not self.status == PeeringStatus.ESTABLISHED:
            self._change_peering_status(PeeringStatus.ESTABLISHING)
            await self._send_message(PeeringHello(initiator_id=self.id))

    async def _handler_loop(self, handler, sleep=0):
        while True:
            await handler()
            await asyncio.sleep(sleep)

    async def _handle_timeout(self):
        if time.time() > self.timeout:
            if not self.status == PeeringStatus.ESTABLISHING:
                self._change_peering_status(PeeringStatus.IDLE)

    async def _handle_incoming_messages(self):
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
                self.rx_input.send(rx_message)

    async def _handle_keepalive(self):
        if self.status == PeeringStatus.ESTABLISHED:
            if time.time() > self.keepalive_send_timeout:
                await self._send_message(PeeringKeepalive())
                self.keepalive_send_timeout = time.time() + \
                    self.keepalive_send_interval

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
        async for message in self.ipfs.pubsub.sub(self.queue_id):
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
