from .config import Config
import logging
from gnupg import GPG
import aioipfs


os.makedirs(Config.gpghome, exist_ok=True)
pg = GPG(gnupghome=Config.gpghome)

class User(object):
    pubkey_cid = pubkey = fingerprint = name = comment = email = None

    def __init__(self, cid):
        self.pubkey_cid = cid
        
    async def _init(self):
        self.parse_own_cid()

    async def get_pubkey(self):
        client = aioipfs.AsyncIPFS()
        self.pubkey = client.get(self.pubkey_cid)
        await client.close()

    async def parse_own_cid(self):
        client = aioipfs.AsyncIPFS()
        # todo: we need to find a way to avoid writing the content out to disk.
        await client.get(self.pubkey_cid, dstdir='.' + self.pubkey_cid)
        await client.close()
        key = open(Config.pubkey_path, 'r')
        self.pubkey = key.read()
        import_result = gpg.import_keys(self.pubkey)
        self.fingerprint = import_result.fingerprints[0]
        self.key_props = gpg.list_keys().key_map[self.fingerprint]
        self.name = self.key_props['uids']


class PeerUser(User):
    pass

class MyUser(User):
    """
The MyUser class extends the user class by adding methods to interact with gpg, e.g. generating keys, signing peer keys, sharing 
signed keys, revoking signatures or sharing revocations.
The fundamental way a user interacts with the web of trust, i.e., gnupg, is through the interactions between MyUser and PeerUser.

This is a departure from the traditional WOT concept of a keyserver. Here, sharing exported signed keys, revocations, importing, et
 c. are explicit and selective operations. With a traditional keyserver, exporting a signature to the server means telling everyone
that you trust the key, and maybe you don't want everyone in the community to know that you are utilizing resources from that peer
 
Alternatively, maybe you disagree with the decisions of the DC engineer at one location and you'd like to revoke your trust . and 
one of your trust database changes are shared implicitly. It's not meant to be 

Config cid has the highest precedence when determining our user, followed by on-disk pubkey file (our users cid is calculated from 
this file).
    """
    def __init__(self):
        pass
    
    async def _init(self, cid = None, name_real = None, name_comment = None, name_email = None):
        if cid is None:
            try:
                self.pubkey_cid = Config.cid
            except:
                try:
                    await self.create_pubkey_cid()
                except:
                    self.generate_keypair(name_real, name_comment, name_email)
                    await self.create_pubkey_cid()
        else:
            self.pubkey_cid = cid
            
        await self.parse_own_cid()

                 
    def generate_keypair(self,
                         name_real,
                         name_comment,
                         name_email,
                         key_type=Config.default_key_type,
                         key_length=Config.default_key_length):
        
        inputdata = gpg.gen_key_input(key_type=key_type,
                                      key_length=key_length,
                                      name_real=name_real,
                                      name_comment=name_comment,
                                      name_email=name_email)
        key = gpg.gen_key(inputdata)
        self.fingerprint = key.fingerprint
        key_data = gpg.export_keys(self.fingerprint)
        
        with open(Config.pubkey_path, 'w+') as f:
            f.write(key_data)
        

    async def create_pubkey_cid(self):
        client = aioipfs.AsyncIPFS()
        async for result in client.add(Config.pubkey_path):
            print(result)
            self.pubkey_cid = result['Hash']
        await client.close()
        
        
    def trust(self, peer: PeerUser, trustlevel):
        gpg.trust_keys([peer.fingerprint], trustlevel)
        

class TrustLevels(object):
    TRUST_UNDEFINED = 'TRUST_UNDEFINED'
    TRUST_NEVER = 'TRUST_NEVER'
    TRUST_MARGINAL = 'TRUST_MARGINAL'
    TRUST_FULLY = 'TRUST_FULLY'
    TRUST_ULTIMATE = 'TRUST_ULTIMATE'
    

