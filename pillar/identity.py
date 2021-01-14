from .keymanager import KeyManager


class LocalIdentity:
    peer_users = []
    peer_nodes = []

    def __init__(self, key_manager: KeyManager,
                 cid: str = None):
        self.key_manager = key_manager
        self.cid = cid


class Node(LocalIdentity):
    def bootstrap(self):
        self.key_manager.generate_local_node_subkey()
        self.cid = \
            self.key_manager.cid
        self.profile = self.create_profile()


class User(LocalIdentity):
    def bootstrap(self, name, email):
        self.key_manager.generate_user_primary_key(name, email)
        self.key_manager.generate_local_user_subkey()
        self.cid = \
            self.key_manager.cid
