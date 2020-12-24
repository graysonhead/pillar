import aioipfs
from .messages import IPRPCMessage, \
    PingRequestCall, \
    PingReplyCall, \
    IPRPCMessageType
from ..exceptions import IPRPCMessageException
import logging
import base64
import asyncio
from urllib.parse import unquote


class Channel:
    """channels are where peers talk"""

    def __init__(self, queue_id: str,
                 own_peer_id: str,
                 ipfs_instance: aioipfs.AsyncIPFS):
        self.own_peer_id = own_peer_id
        self.queue_id = queue_id
        self.ipfs = ipfs_instance
        self.messages = []
        self.logger = logging.getLogger(self.__repr__())

    async def send_message(self, message: IPRPCMessage):
        """send message in pubsub channel"""
        message.src_peer = self.own_peer_id
        serialized_message = message.serialize_to_json()
        self.logger.info(f"Sending message: {message}")
        message_bytes = self._encode_message(serialized_message)
        self.logger.info(f"Sending raw message {message_bytes}")
        async with self.ipfs as cli:
            await cli.pubsub.pub(self.queue_id,
                                 message_bytes.decode())

    def _encode_message(self, message: str):
        return base64.b64encode(message.encode('utf-8'))

    def _decode_message(self, message: bytes):
        # Decode byte-encoding and Convert any URL safe encoded chars
        message = unquote(message.decode('utf-8'))
        try:
            return base64.b64decode(message).decode()
        except Exception as e:
            self.logger.warning(f"Invalid encoding on received message: {e} "
                                f"raw_message: {message}")
            raise e

    def _validate_message(self, raw_message: str):
        try:
            return IPRPCMessage.deserialize_from_json(
                raw_message)
        except IPRPCMessageException as e:
            self.logger.warning(f"Invalid message received: {e}")
            return False

    def subscribe(self):
        """Subscribes to pubsub channel and processes messages"""
        loop = asyncio.get_event_loop()
        loop.create_task(self.get_messages())
        loop.run_forever()

    async def process_messages(self):
        self.logger.info(f"Processing messages: {self.messages}")
        while self.messages:
            message = self.messages.pop()
            # Only process the message if it is for us
            if (message.broadcast and message.src_peer != self.own_peer_id)\
                    or message.dst_peer == self.own_peer_id:
                if type(message.call) == PingRequestCall:
                    response = IPRPCMessage(IPRPCMessageType.INLINE,
                                            dst_peer=message.src_peer,
                                            src_peer=self.own_peer_id,
                                            call=PingReplyCall(),
                                            )
                    await self.send_message(response)
            else:
                self.logger.info(f"Skip processing {message}, it is from us.")

    async def get_messages(self):
        """Retrieves, validates, and stores messages"""
        self.logger.info("Checking for new messages")
        async with self.ipfs as cli:
            async for raw_message in cli.pubsub.sub(self.queue_id):
                serialized_data = self._decode_message(
                    raw_message.get('data')
                )
                message = self._validate_message(
                        serialized_data)
                if message:
                    self.messages.append(message)
                    self.logger.info(f"Received message from peer "
                                     f"{message.src_peer}"
                                     f": {message}")
                    await self.process_messages()

    def __repr__(self):
        return f"<Channel: queue_id={self.queue_id}>"
