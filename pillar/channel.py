import aioipfs


class Channel:
    """channels are where peers talk"""

    def __init__(self, qid):
        self.qid = qid
        self.messages = []

    async def send_message(self, message):
        """send message in pubsub channel"""
        async with aioipfs.AsyncIPFS() as cli:
            await cli.pubsub.pub(self.qid, message)

    async def get_messages(self):
        """gets messages from pubsub channel"""
        messages = []
        async with aioipfs.AsyncIPFS() as cli:
            async for message in cli.pubsub.sub(self.qid):
                messages.append(message)
            self.messages = messages
