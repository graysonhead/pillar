import aioipfs
import asyncio
import logging
from urllib.parse import unquote
from queue import Queue
from threading import Thread

_term = object()


def start_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


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

    async def send_messages_from_queue(self, queue: Queue):
        while True:
            message = queue.get()
            if message == _term:
                break
            else:
                await self.send_message(message)

    async def retrieve_messages_to_queue(self, queue: Queue):
        while True:
            async with self.ipfs as ipfs:
                async for message in ipfs.pubsub.sub(self.queue_id):
                    self.logger.info(f"Got message: {message}")
                    queue.put(unquote(message['data'].decode('utf-8')))

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
                 tx_queue_id: str):
        self.peer_id = peer_id
        self.rx_queue_id = rx_queue_id
        self.tx_queue_id = tx_queue_id
        self.logger = logging.getLogger(self.__repr__())
        # Set up Transmit Thread
        self.tx_queue = Queue()
        tx_loop = asyncio.new_event_loop()
        self.tx_thread = Thread(target=self._create_tx_callchannel,
                                args=(tx_loop, )
                                )
        self.logger.info(f"Spawned tx_thread {self.tx_thread}")
        # Set up receive thread
        self.rx_queue = Queue()
        rx_loop = asyncio.new_event_loop()
        self.rx_thread = Thread(target=self._create_rx_callchannel,
                                args=(rx_loop, ))
        self.logger.info(f"Spawned rx_thread {self.tx_thread}")

    def start_threads(self):
        self.tx_thread.start()
        self.rx_thread.start()

    def _create_rx_callchannel(self, loop):
        asyncio.set_event_loop(loop)
        ipfs_instance = aioipfs.AsyncIPFS()
        channel = CallChannel(self.rx_queue_id, ipfs_instance)
        loop.run_until_complete(
            channel.retrieve_messages_to_queue(self.rx_queue)
        )

    def _create_tx_callchannel(self, loop):
        asyncio.set_event_loop(loop)
        ipfs_instance = aioipfs.AsyncIPFS()
        channel = CallChannel(self.tx_queue_id, ipfs_instance)
        loop.run_until_complete(
            channel.send_messages_from_queue(self.tx_queue)
        )

    def _stop_threads(self):
        self.rx_queue.put(_term)

    def __repr__(self):
        return f"<PeerChannel: {self.peer_id}>"
