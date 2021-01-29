import aioipfs
from .multiproc import PillarThreadMixIn, \
    PillarThreadMethodsRegister, \
    PillarWorkerThread


class IPFSWorkerMethodsRegister(PillarThreadMethodsRegister):
    pass


class IPFSClient:

    def __init__(self, aioipfs_config: dict = None):
        self.aioipfs_config = aioipfs_config or {}

    async def get_file(self, cid: str, dstdir='.') -> None:
        client = self.get_client()
        await client.get(cid, dstdir)
        await client.close()

    async def add_file(self, *files: str, **kwargs):
        client = self.get_client()
        await client.add(*files, **kwargs)
        await client.close()

    async def add_str(self, *args: str, **kwargs):
        client = self.get_client()
        result = await client.add_str(*args, **kwargs)
        await client.close()
        return result

    async def send_pubsub_message(self, queue_id: str, message: str) -> None:
        client = self.get_client()
        await client.pubsub.pub(queue_id, message)
        await client.close()

    async def get_pubsub_message(self, queue_id: str) -> str:
        client = self.get_client()
        async for message in client.pubsub.sub(queue_id):
            await client.close()
            yield message

    async def get_id(self) -> dict:
        client = self.get_client()
        id = await client.core.id()
        await client.close()
        return id

    def get_client(self) -> aioipfs.AsyncIPFS:
        return aioipfs.AsyncIPFS(**self.aioipfs_config)


class IPFSWorker(PillarWorkerThread):
    methods_register_class = IPFSWorkerMethodsRegister

    def __init__(self, ipfs_client: IPFSClient = None):
        super().__init__()
        self.ipfs_client = ipfs_client or IPFSClient()

    @IPFSWorkerMethodsRegister.register_method
    async def get_file(self, cid: str, dstdir='.') -> None:
        return await self.ipfs_client.get_file(cid, dstdir=dstdir)

    @IPFSWorkerMethodsRegister.register_method
    async def add_str(self, *args: str, **kwargs):
        return await self.ipfs_client.add_str(*args, **kwargs)

    @IPFSWorkerMethodsRegister.register_method
    async def add_file(self, *files: str, **kwargs):
        return await self.ipfs_client.add_file(*files, **kwargs)


class IPFSMixIn(PillarThreadMixIn):
    queue_thread_class = IPFSWorker
    interface_name = "ipfs"
