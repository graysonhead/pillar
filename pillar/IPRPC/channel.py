import aioipfs
from .messages import IPRPCMessage
from ..exceptions import IPRPCMessageException
import logging


class Channel:
    """channels are where peers talk"""

    def __init__(self, queue_id, ipfs_instance: aioipfs.AsyncIPFS):
        self.queue_id = queue_id
        self.ipfs = ipfs_instance
        self.messages = []
        self.logger = logging.getLogger(self.__repr__())

    async def send_message(self, message: IPRPCMessage):
        """send message in pubsub channel"""
        serialized_message = message.serialize_to_json()
        self.logger.info(f"Sending message: {serialized_message}")
        async with self.ipfs as cli:
            await cli.pubsub.pub(self.queue_id, serialized_message)

    async def get_messages(self):
        """gets messages from pubsub channel"""
        messages = []
        async with self.ipfs as cli:
            async for raw_message in cli.pubsub.sub(self.queue_id):
                try:
                    message = raw_message.deserialize_from_json()
                except IPRPCMessageException as e:
                    self.logger.warning(f"Invalid message received: {e}")
                messages.append(message)
            self.messages = messages

    def __repr__(self):
        return f"<Channel: queue_id={self.queue_id}>"
