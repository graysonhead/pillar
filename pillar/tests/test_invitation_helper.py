from unittest.mock import patch, MagicMock
from pillar.config import PillardConfig

from pillar.invitation_helper import InvitationHelper
from pillar.IPRPC.messages import FingerprintMessage, InvitationMessage

from unittest import TestCase


class MockKeyManagerInterface(MagicMock):
    import_or_update_peer_key = MagicMock()
    import_peer_key_from_cid = MagicMock()
    generate_user_primary_key = MagicMock()
    generate_local_node_subkey = MagicMock()
    get_keys = MagicMock()
    get_private_key_for_key_type = MagicMock()
    get_key_from_keyring = MagicMock()
    get_user_primary_key_cid = MagicMock(return_value='bogus')
    create_fingerprint_message = MagicMock()
    get_fingerprint_cid = MagicMock()


class MockCIDMessengerInterface(MagicMock):
    add_unencrypted_message_to_ipfs = MagicMock()
    add_encrypted_message_to_ipfs_for_peer = MagicMock()
    get_unencrypted_message_from_cid = MagicMock(
        return_value=FingerprintMessage(
            public_key_cid='bogus', fingerprint='bogus'
        )
    )
    get_and_decrypt_message_from_cid = MagicMock(
        return_value=InvitationMessage(
            public_key_cid='bogus',
            preshared_key='bogus',
            channels_per_peer=1,
            channel_rotation_period=1
        )
    )


class MockInterface(MagicMock):
    key_manager = MockKeyManagerInterface
    cid_messenger = MockCIDMessengerInterface


class TestInvitationHelper(TestCase):
    @patch("pillar.invitation_helper.InvitationHelperInterface",
           new_callable=MockInterface)
    def setUp(self, *args):
        self.ih = InvitationHelper(PillardConfig(), MagicMock(), MagicMock())

    def test_create_invitation(self):
        self.ih.create_invitation('fake_cid')
        self.ih.interface.cid_messenger.get_unencrypted_message_from_cid.\
            assert_called_with('fake_cid')
        self.ih.interface.key_manager.import_or_update_peer_key.assert_called()
        self.ih.interface.cid_messenger.\
            add_encrypted_message_to_ipfs_for_peer.assert_called()

    def test_receive_invitation_by_cid(self):
        self.ih.receive_invitation_by_cid('bogus')
        self.ih.interface.cid_messenger.get_and_decrypt_message_from_cid.\
            assert_called_with('bogus', verify=False)
        self.ih.interface.key_manager.import_or_update_peer_key.assert_called()
