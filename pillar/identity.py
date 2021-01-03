from .keymanager import KeyManager, PillarKeyType, PeerUser
from .config import Config
from uuid import uuid4
import json
import aioipfs
import asyncio


class PublicProfile:
    def __init__(self, config: Config, profile_cid: str = None):
        self.profile_cid = profile_cid
        self.pubkey = None
        self.primary_key_fingerprint = None
        self.name = None
        self.email = None
        self.exported_attributes = [
            'pubkey', 'primary_fingerprint', 'name', 'email']
        self.config = config
        self.ipfs = aioipfs.AsyncIPFS()
        if self.profile_cid is not None:
            self.load_profile()

    def load_profile(self):
        self.ipfs.get(self.profile_cid)

    def serialize_to_json(self):
        return json.dumps({k: v for k, v in self.attributes.items()})


class Invitation:
    def __init__(
            self, config: Config, profile: PublicProfile, listen_channels=None):
        self.profile = profile
        if listen_channels is None:
            for _ in range(config.listen_channels_per_peer):
                self.listen_channels.append(uuid4())
        else:
            self.listen_channels = listen_channels


class NodeProfile(PublicProfile):
    def __init__(self, profile_cid: str):
        super().__init__(profile_cid)
        self.node_subkey_fingerprint = None
        self.exported_attributes.extend(
            ['node_subkey_fingerprint', 'resources'])


class UserProfile(PublicProfile):
    def __init__(self, profile_cid: str):
        super().__init__(profile_cid)
        self.user_subkey_fingerprint = None
        self.exported_attributes.extend(
            ['user_subkey_fingerprint', 'biotext', 'photo_cid'])


class LocalIdentity:
    peer_users = []
    peer_nodes = []

    def __init__(self, key_manager: KeyManager,
                 cid: str = None):
        self.loop = asyncio.get_event_loop()
        self.key_manager = key_manager
        self.cid = cid

    def add_peer_user(self, peer: PeerUser):
        self.peer_users.append(peer)


class Node(LocalIdentity):
    def bootstrap(self):
        self.key_manager.generate_local_node_subkey()
        self.cid = \
            self.key_manager.get_cid_for_key_type(PillarKeyType.NODE_SUBKEY)
        self.profile = self.create_profile()


class User(LocalIdentity):
    def bootstrap(self, name, email):
        self.key_manager.generate_user_primary_key(name, email)
        self.key_manager.generate_local_user_subkey()
        self.cid = \
            self.key_manager.get_cid_for_key_type(PillarKeyType.USER_SUBKEY)
