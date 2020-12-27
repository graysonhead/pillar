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


class Identity:
    primary_key_cid = None
    subkey_cid = None
    pubkey = None
    key_props = None
    fingerprint = None
    name = None
    comment = None
    email = None


class Node(Identity):
    pass


class User(Identity):
    """A generic user."""

    def __init__(self,
                 config: Config,
                 ipfs_instance: aioipfs.AsyncIPFS,
                 cid):
        self.config = config
        self.gpg = GPG(gnupghome=os.path.abspath(self.config.gpghome))
        self.ipfs = ipfs_instance
        # these are the same for now
        self.primary_key_cid = self.subkey_cid = cid or self.config.subkey_cid
        self.profile_cid = None

    async def _parse_cid(self):
        """Parse the cid associated with this user"""
        # todo: we need a central place to manage where we write ipfs
        # content to disk.
        if not os.path.isfile(self.config.pubkey_path):
            await self.ipfs.get(self.primary_key_cid,
                                dstdir=os.path.join(self.config.ipfsdir,
                                                    self.subkey_cid))
        with open(self.config.pubkey_path, 'r') as keyfile:
            keydata = keyfile.read()
            import_result = self.gpg.import_keys(keydata)
            self.fingerprint = import_result.fingerprints[0]
            self.key_props = self.gpg.list_keys().key_map[self.fingerprint]
            self.name = self.key_props['uids']

    async def import_key_from_cid(self, cid):
        """import a key to gpg database identified by the given cid"""
        keypath = os.path.join(self.config.ipfsdir, cid)
        if not os.path.isdir(keypath):
            os.makedirs(keypath)
            await self.ipfs.get(cid, dstdir=keypath)
        with open(os.path.join(keypath, cid), 'r') as key:
            data = key.read()
            import_result = self.gpg.import_keys(data)


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
            self.primary_key_cid = cid
        else:
            self.primary_key_cid = self.config.primary_key_cid
            if self.primary_key_cid is None:
                self.generate_keypair(name_real, name_comment, name_email)
                await self.create_primary_pubkey_cid()
        await self._parse_cid()

    def generate_keypair(self,
                         name_real,
                         name_comment,
                         name_email,
                         key_type=None,
                         key_length=None,
                         subkey_type=None,
                         subkey_length=None,
                         expire_date=None):
        """Generate a new keypair and assign it to MyUser"""
        if key_type is None:
            key_type = self.config.default_key_type
        if key_length is None:
            key_length = self.config.default_key_length
        if subkey_type is None:
            subkey_type = self.config.default_subkey_type
        if subkey_length is None:
            subkey_length = self.config.default_subkey_length
        if expire_date is None:
            expire_date = self.config.default_subkey_duration

        inputdata = self.gpg.gen_key_input(key_type=key_type,
                                           key_length=key_length,
                                           subkey_type=subkey_type,
                                           subkey_length=subkey_length,
                                           expire_date=expire_date,
                                           name_real=name_real,
                                           name_comment=name_comment,
                                           name_email=name_email,
                                           )
        from pprint import pprint
        key = self.gpg.gen_key(inputdata)
        self.fingerprint = key.fingerprint
        key_data = self.gpg.export_keys(self.fingerprint)
        pprint(key_data)

        with open(self.config.pubkey_path, 'w+') as file:
            file.write(key_data)

    async def create_primary_pubkey_cid(self):
        """Add the user's public key to ipfs"""
        with open(self.config.pubkey_path) as f:
            key_str = f.read()
        cid = await self.ipfs.core.add_str(key_str)
        self.config.primary_key_cid = cid['Hash']
        self.config.subkey_cid = cid['Hash']
        self.primary_key_cid = cid['Hash']
        self.subkey_cid = cid['Hash']

    def encrypt_call(self, call: IPRPCCall, peer: PeerUser):
        """Encrypt a payload for insertion in a message"""
        return self.gpg.encrypt(call.serialize_to_json(), peer.fingerprint)

    def decrypt_call(self, crypt_call, peercid):
        peer = PeerUser(self.config, self.ipfs, peercid)
        call_json = self.gpg.decrypt(crypt_call)
        return IPRPCCall(


    def trust(self, peer: PeerUser,
              trustlevel: TrustLevel=TrustLevel.TRUST_FULLY):
        """Set the trust level for the given peer user's key"""
        print(peer.fingerprint)
        self.gpg.trust_keys([peer.fingerprint], trustlevel)
