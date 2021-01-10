from .keymanager import KeyManager, PillarKeyType, PeerUser
import asyncio


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
