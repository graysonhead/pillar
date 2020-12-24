import aioipfs
from .messages import IPRPCMessage
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
        message_bytes = self._encode_message(serialized_message)
        async with self.ipfs as cli:
            await cli.pubsub.pub(self.queue_id,
                                 message_bytes.decode())

    @staticmethod
    def _encode_message(message: str):
        return base64.b64encode(message.encode('utf-8'))

    def _decode_message(self, message: bytes):
        try:
            return base64.b64decode(message.decode('utf-8')).decode()
        except Exception as e:
            self.logger.warning(f"Invalid encoding on received message: {e}")

    def _validate_message(self, raw_message: str):
        try:
            return IPRPCMessage.deserialize_from_json(
                raw_message)
        except IPRPCMessageException as e:
            self.logger.warning(f"Invalid message received: {e}")
            return False

    async def get_messages(self):
        """gets messages from pubsub channel"""
        async with self.ipfs as cli:
            async for raw_message in cli.pubsub.sub(self.queue_id):
                serialized_data = \
                    self._decode_message(raw_message.get('data'))
                message = self._validate_message(
                        serialized_data)
                if message:
                    self.messages.append(message)
                    self.logger.info(f"Received message from peer "
                                     f"{raw_message.get('from').decode()}"
                                     f": {message}")

    def __repr__(self):
        return f"<Channel: queue_id={self.queue_id}>"
