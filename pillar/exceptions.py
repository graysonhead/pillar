class IPRPCMessageException(Exception):
    pass


class KeyTypeNotPresent(Exception):
    """
    Raised when trying to load a key type which isnt present on the
    instance.
    """


class KeyNotInKeyring(Exception):
    """
    Raised when attemting to update a key with one that's not already
    in the keyring.
    """


class WontUpdateToStaleKey(Exception):
    """
    Raised when attemting to update a key with one that is stale.
    """


class MessageCouldNotBeVerified(Exception):
    """
    Raised when a message signature cannot be verified.
    """


class KeyNotVerified(Exception):
    """
    Raised when attemting to update a key with one that is not validated
    by an existing key in the keyring.
    """


class CannotImportSamePrimaryFingerprint(Exception):
    """
    Raised in import_peer_key if an attempt is made to import a key whose
    primary fingerprint is already known to the key manager. update_peer_key
    should be used in that case instead.
    """


class KeyTypeAlreadyPresent(Exception):
    """
    Raised when trying to generate a primary key type that already exists on
    this node. I.e.: you can't make another user primary key if you already
    have one. Same goes for the registration primary. Delete first, then
    proceed if that's what you want.
    """
