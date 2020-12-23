import aioipfs
from .messages import IPRPCMessage, IPRPCRegistry
from ..exceptions import IPRPCMessageException
import logging
import base64


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
        message_bytes = base64.b64encode(serialized_message.encode())
        print(message_bytes)
        async with self.ipfs as cli:
            await cli.pubsub.pub(self.queue_id,
                                 message_bytes.decode())

    async def get_messages(self):
        """gets messages from pubsub channel"""
        messages = []
        async with self.ipfs as cli:
            async for raw_message in cli.pubsub.sub(self.queue_id):
                raw_message_string = raw_message.get('data').decode('utf-8')
                serialized_data = base64.b64decode(raw_message_string).decode()
                try:
                    message = IPRPCMessage.deserialize_from_json(
                        serialized_data)
                except IPRPCMessageException as e:
                    self.logger.warning(f"Invalid message received: {e}")
                messages.append(message)
                self.logger.info(f"Received message from peer "
                                 f"{raw_message.get('from').decode()}"
                                 f": {message}")
            self.messages = messages

    def __repr__(self):
        return f"<Channel: queue_id={self.queue_id}>"
