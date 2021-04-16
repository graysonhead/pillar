from .keymanager import KeyManagerCommandQueueMixIn
from .IPRPC.cid_messenger import CIDMessengerMixIn
from .IPRPC.messages import FingerprintMessage, InvitationMessage
from .multiproc import MixedClass
from .config import PillardConfig
from .exceptions import WrongMessageType
import multiprocessing as mp
import logging
from uuid import uuid4


class InvitationHelperInterface(KeyManagerCommandQueueMixIn,
                                CIDMessengerMixIn,
                                metaclass=MixedClass):
    pass


class InvitationHelper:
    def __init__(self,
                 config: PillardConfig,
                 command_queue: mp.Queue,
                 output_queue: mp.Queue
                 ):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.interface = InvitationHelperInterface(
            str(self),
            command_queue=command_queue,
            output_queue=output_queue)

    def create_invitation(self, peer_fingerprint_cid):
        fingerprint, pubkey_cid = self._get_info_from_fingerprint_cid(
            peer_fingerprint_cid)

        self.interface.key_manager.import_or_update_peer_key(
            pubkey_cid)

        invitation = InvitationMessage(
            public_key_cid=self.interface.key_manager.
            get_user_primary_key_cid(),
            preshared_key=str(uuid4()),
            channels_per_peer=self.config.get_value('channels_per_peer'),
            channel_rotation_period=self.config.get_value('channels_per_peer')
        )
        self.logger.info(
            f'Creating invitation for peer {peer_fingerprint_cid}')
        return self.interface.cid_messenger.\
            add_encrypted_message_to_ipfs_for_peer(invitation, fingerprint)

    def _get_info_from_fingerprint_cid(self, fingerprint_cid):
        self.logger.info(
            f'Getting peer fingerprint info from cid: {fingerprint_cid}')
        fingerprint_info = self.interface.cid_messenger.\
            get_unencrypted_message_from_cid(fingerprint_cid)
        if not type(fingerprint_info) is FingerprintMessage:
            raise WrongMessageType(type(fingerprint_info))

        return fingerprint_info.fingerprint, fingerprint_info.public_key_cid

    def receive_invitation_by_cid(self, cid: str):
        self.logger.info(f'Receiving invitation from cid: {cid}')
        invitation = self.interface.cid_messenger.\
            get_and_decrypt_message_from_cid(cid, verify=False)
        if not type(invitation) is InvitationMessage:
            raise WrongMessageType(type(invitation))
        self.interface.key_manager.\
            import_or_update_peer_key(invitation.public_key_cid)
