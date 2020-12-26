import os
from enum import Enum
import aioipfs
from gnupg import GPG
from pillar.IPRPC.messages import IPRPCCall
from pillar.config import Config


class TrustLevel(Enum):
    """These are the trust levels defined in gnupg"""
    TRUST_UNDEFINED = 'TRUST_UNDEFINED'
    TRUST_NEVER = 'TRUST_NEVER'
    TRUST_MARGINAL = 'TRUST_MARGINAL'
    TRUST_FULLY = 'TRUST_FULLY'
    TRUST_ULTIMATE = 'TRUST_ULTIMATE'


class User:
    """A generic user."""
    pubkey_cid = None
    pubkey = None
    key_props = None
    fingerprint = None
    name = None
    comment = None
    email = None

    def __init__(self,
                 config: Config,
                 ipfs_instance: aioipfs.AsyncIPFS,
                 cid):
        self.config = config
        self.gpg = GPG(gnupghome=os.path.abspath(self.config.gpghome))
        self.ipfs = ipfs_instance
        self.pubkey_cid = cid

    async def _parse_cid(self):
        """Parse the cid associated with this user"""
        # todo: we need a central place to manage where we write ipfs
        # content to disk.
        if not os.path.isfile(self.config.pubkey_path):
            await self.ipfs.get(self.pubkey_cid,
                                dstdir=os.path.join(self.config.ipfsdir,
                                                    self.pubkey_cid))
        key = open(self.config.pubkey_path, 'r')
        self.pubkey = key.read()
        import_result = self.gpg.import_keys(self.pubkey)
        self.fingerprint = import_result.fingerprints[0]
        self.key_props = self.gpg.list_keys().key_map[self.fingerprint]
        self.name = self.key_props['uids']


class PeerUser(User):
    """A peer user represents another person on the network."""


class MyUser(User):
    """
    The MyUser class extends the user class by adding methods to interact with
    gpg, e.g generating keys,signing peer keys, sharing signed keys, revoking
    signatures or sharing revocations.
    """

    def __init__(self,
                 config: Config,
                 ipfs_instance: aioipfs.AsyncIPFS,
                 cid=None):
        super().__init__(config, ipfs_instance, cid)

    async def bootstrap(self,
                        cid=None,
                        name_real=None,
                        name_comment=None,
                        name_email=None
                        ):
        if cid is not None:
            self.pubkey_cid = cid
        else:
            self.pubkey_cid = self.config.user_cid
            if self.pubkey_cid is None:
                self.generate_keypair(name_real, name_comment, name_email)
                await self.create_pubkey_cid()
        await self._parse_cid()

    def generate_keypair(self,
                         name_real,
                         name_comment,
                         name_email,
                         key_type=None,
                         key_length=None):
        """Generate a new keypair and assign it to MyUser"""
        if key_type is None:
            key_type = self.config.default_key_type
        if key_length is None:
            key_length = self.config.default_key_length

        inputdata = self.gpg.gen_key_input(key_type=key_type,
                                           key_length=key_length,
                                           name_real=name_real,
                                           name_comment=name_comment,
                                           name_email=name_email)
        key = self.gpg.gen_key(inputdata)
        self.fingerprint = key.fingerprint
        key_data = self.gpg.export_keys(self.fingerprint)

        with open(self.config.pubkey_path, 'w+') as file:
            file.write(key_data)

    async def create_pubkey_cid(self):
        """Add the user's public key to ipfs"""
        with open(self.config.pubkey_path) as f:
            key_str = f.read()
        cid = await self.ipfs.core.add_str(key_str)
        self.config.user_cid = cid
        self.pubkey_cid = cid

    def encrypt_call(self, call: IPRPCCall, peer: PeerUser):
        """Encrypt a payload for insertion in a message"""
        return self.gpg.encrypt(call.serialize_to_json, peer.fingerprint)

    def trust(self, peer: PeerUser,
              trustlevel: TrustLevel = TrustLevel.TRUST_FULLY):
        """Set the trust level for the given peer user's key"""
        self.gpg.trust_keys([peer.fingerprint], trustlevel)
