import aioipfs
import asyncio


class IPFSClient:

    def __init__(self, aioipfs_config: dict = None):
        self.aioipfs_config = aioipfs_config or {}
        self.client = None
        self.loop = None

    async def send_pubsub_message(self, queue_id: str, message: str):
        await self.check_client_exists()
        await self.client.pubsub.pub(queue_id, message)

    async def get_pubsub_message(self, queue_id: str):
        await self.check_client_exists()
        async for message in self.client.pubsub.sub(queue_id):
            yield message

    async def get_id(self) -> dict:
        await self.check_client_exists()
        id = await self.client.core.id()
        return id

    async def check_client_exists(self):
        if not self.client:
            self.client = aioipfs.AsyncIPFS(**self.aioipfs_config)
            self.loop = asyncio.get_event_loop()

    async def close_client(self):
        await self.client.close()

    def __del__(self):
        asyncio.run(self.check_client_exists())
        asyncio.run(self.close_client())
