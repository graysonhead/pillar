from .db import PillarDatastoreMixIn, Key


class Peer(PillarDatastoreMixIn):
    model = Key

    def __init__(self):
        self.fingerprint = None
        self.key = None
