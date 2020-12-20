import aioipfs

# todo: should probably make communities run in separate processes and implement an interprocess queue to pass messages using a
# separate control process. Could maybe make an API, too.
class Community(object):
    """
    The Community class handles the operations related to the ipfs pubsub topic that represents a given compute community.
    Being a community member means watching the topic for messages and responding to peers. 
    """
    def __init__(self, topic):
        self.topic = topic
        

    async def send_message(self, source, destination, message):
        """all args identified by cid"""
        formatted_message = source + ',' + destination + ',' + message
        async with aioipfs.AsyncIPFS() as cli:
            await cli.pubsub.pub(self.topic, formatted_message)

    async def get_messages(self):
        messages = []
        async with aioipfs.AsyncIPFS() as cli:
            async for message in cli.pubsub.sub(self.topic):
                messages.append(self.parse_message(message))
            self.messages = messages

    def parse_message(self, message):
        mlist = message.split(',')
        ret["source"] = mlist[0]
        ret["destination"] = mlist[1]
        ret["message"] = mlist[2]
        return ret
