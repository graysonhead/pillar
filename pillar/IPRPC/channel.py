import aioipfs
import logging
from urllib.parse import unquote


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

    async def get_messages(self):
        async with self.ipfs as ipfs:
            async for message in ipfs.pubsub.sub(self.queue_id):
                self.logger.info(f"Got message: "
                                 f"{message}")
                yield unquote(message['data'].decode('utf-8'))

    def __repr__(self):
        return f"<CallChannel: queue_id={self.queue_id}>"
