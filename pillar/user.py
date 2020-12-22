import os
from enum import Enum
import aioipfs
from gnupg import GPG
from .config import Config

os.makedirs(Config.gpghome, exist_ok=True)
gpg = GPG(gnupghome=Config.gpghome)


class User:
    """A generic user."""
    pubkey_cid = None
    pubkey = None
    key_props = None
    fingerprint = None
    name = None
    comment = None
    email = None

    def __init__(self, cid):
        self.pubkey_cid = cid

    async def get_pubkey(self):
        """get the public key associated with our user from ipfs"""
        client = aioipfs.AsyncIPFS()
        self.pubkey = client.get(self.pubkey_cid)
        await client.close()

    async def parse_own_cid(self):
        """Parse the cid associated with our user"""
        client = aioipfs.AsyncIPFS()
        # todo: we need to find a way to manage where we write the
        # content to disk.
        await client.get(self.pubkey_cid, dstdir='.' + self.pubkey_cid)
        await client.close()
        key = open(Config.pubkey_path, 'r')
        self.pubkey = key.read()
        import_result = gpg.import_keys(self.pubkey)
        self.fingerprint = import_result.fingerprints[0]
        self.key_props = gpg.list_keys().key_map[self.fingerprint]
        self.name = self.key_props['uids']


class PeerUser(User):
    """A peer user represents another person on the network."""
    async def _init(self):
        self.parse_own_cid()


class MyUser(User):
    """
    The MyUser class extends the user class by adding methods to interact with
    gpg, e.g generating keys,signing peer keys, sharing signed keys, revoking
    signatures or sharing revocations.
    """

    def __init__(self, cid=None):
        super(self.__class__).__init__(self, cid)

    async def _init(self,
                    cid=None,
                    name_real=None,
                    name_comment=None,
                    name_email=None
                    ):
        if cid is not None:
            self.pubkey_cid = cid
        else:
            self.pubkey_cid = Config.cid
            if self.pubkey_cid is None:
                try:
                    await self.create_pubkey_cid()
                except Exception:
                    self.generate_keypair(name_real, name_comment, name_email)
                    await self.create_pubkey_cid()

        await self.parse_own_cid()

    def generate_keypair(self,
                         name_real,
                         name_comment,
                         name_email,
                         key_type=Config.default_key_type,
                         key_length=Config.default_key_length):
        """Generate a new keypair and assign it to MyUser"""

        inputdata = gpg.gen_key_input(key_type=key_type,
                                      key_length=key_length,
                                      name_real=name_real,
                                      name_comment=name_comment,
                                      name_email=name_email)
        key = gpg.gen_key(inputdata)
        self.fingerprint = key.fingerprint
        key_data = gpg.export_keys(self.fingerprint)

        with open(Config.pubkey_path, 'w+') as file:
            file.write(key_data)

    async def create_pubkey_cid(self):
        """Add the user's public key to ipfs"""
        client = aioipfs.AsyncIPFS()
        async for result in client.add(Config.pubkey_path):
            self.pubkey_cid = result['Hash']
        await client.close()

    @staticmethod
    def trust(peer: PeerUser, trustlevel):
        """Set the trust level for the given peer user's key"""
        gpg.trust_keys([peer.fingerprint], trustlevel)


class TrustLevels(Enum):
    """These are the trust levels defined in gnupg"""
    TRUST_UNDEFINED = 'TRUST_UNDEFINED'
    TRUST_NEVER = 'TRUST_NEVER'
    TRUST_MARGINAL = 'TRUST_MARGINAL'
    TRUST_FULLY = 'TRUST_FULLY'
    TRUST_ULTIMATE = 'TRUST_ULTIMATE'
