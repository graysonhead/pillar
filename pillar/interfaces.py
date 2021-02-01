from .ipfs import IPFSMixIn
from .db import DBMixIn
from .multiproc import MixedClass


class PillarInterfaces(DBMixIn,
                       IPFSMixIn,
                       metaclass=MixedClass):
    pass
