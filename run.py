from pprint import pprint
from pillar.user import MyUser, PeerUser, TrustLevel
from pillar.config import Config
from pillar.IPRPC.channel import Channel
from pillar.IPRPC.messages import IPRPCMessage, PingReplyCall, PingRequestCall

from gnupg import GPG
import asyncio
import aioipfs
import os
import sys


# setup a config directory and file for our test users

test_user_a_path = os.path.join(os.getcwd(), '.testusera')
test_user_b_path = os.path.join(os.getcwd(), '.testuserb')

os.makedirs(test_user_a_path, exist_ok=True)
os.makedirs(test_user_b_path, exist_ok=True)
configpath_a = os.path.join(test_user_a_path, 'config.yaml')
configpath_b = os.path.join(test_user_b_path, 'config.yaml')

# file needs to exist already? Why filenotfound when open a+ in Config class??

with open(configpath_a, 'a+') as f:
    pass

with open(configpath_b, 'a+') as f:
    pass


# create our config instance and change settings for our test users.
config_a = Config(configpath_a)
config_a.gpghome = test_user_a_path
config_a.configdir = test_user_a_path
config_a.pubkey_path = os.path.join(test_user_a_path, 'key.pub')
config_a.ipfsdir = os.path.join(test_user_a_path, 'ipfs')

config_b = Config(configpath_b)
config_b.gpghome = test_user_b_path
config_b.configdir = test_user_b_path
config_b.pubkey_path = os.path.join(test_user_b_path, 'key.pub')
config_b.ipfsdir = os.path.join(test_user_b_path, 'ipfs')


# Of course, each user will need one ipfs!

ipfs_instance_a = aioipfs.AsyncIPFS()
ipfs_instance_b = aioipfs.AsyncIPFS()

# this is redundant in our case, but some configurations may have a separate gpghome and
# configdir. This would be true, for example, if someone wanted to integrate the trust relationships
# from pillar with the default gpg trust database at ~/.gpg
# By default, pillar keeps its trust database separate from this.

os.makedirs(config_a.gpghome, exist_ok=True)
os.makedirs(config_b.gpghome, exist_ok=True)


# create our two users. A typical peer instace will have only one MyUser, but this is a test
# so we're going to bootstrap two and have them echange their cids before sending encrypted
# messages over ipfs pubsub. Generally, you'd exchange your cids through a messaging service
# like signal or irc, but here, we're sharing an in-memory string between our test users. :)

user_a = MyUser(config_a, ipfs_instance_a)
user_b = MyUser(config_b, ipfs_instance_b)

loop = asyncio.get_event_loop()
loop.run_until_complete(user_a.bootstrap(name_real="fakeuser_a",
                                         name_comment="notreal",
                                         name_email="fakeuser_a@pillarcloud.org"))

loop.run_until_complete(user_b.bootstrap(name_real="fakeuser_b",
                                         name_comment="notreal",
                                         name_email="fakeuser_b@pillarcloud.org"))

# now the users should save the config because they bootstrapped the user. This keeps
# the cid for next time.

user_a.config.save()
user_b.config.save()

pprint(user_a.gpg.list_keys())

# We'll name our trasmission and receive channels from the perspective of user_a
# to avoid confusion.

user_a_tx = Channel("rendezvous_channel1", user_a.subkey_cid, ipfs_instance_a)
user_a_rx = Channel("rendezvous_channel2", user_a.subkey_cid, ipfs_instance_a)

user_b_tx = Channel("rendezvous_channel2", user_b.subkey_cid, ipfs_instance_b)
user_b_rx = Channel("rendezvous_channel1", user_b.subkey_cid, ipfs_instance_b)

print(user_b.subkey_cid)
peer_a = PeerUser(config_a, ipfs_instance_a, user_a.subkey_cid)
peer_b = PeerUser(config_b, ipfs_instance_b, user_b.subkey_cid)
loop.run_until_complete(peer_a._parse_cid())
loop.run_until_complete(peer_b._parse_cid())

os.makedirs(config_a.ipfsdir, exist_ok=True)
os.makedirs(config_b.ipfsdir, exist_ok=True)

print(peer_b.subkey_cid)
loop.run_until_complete(user_a.import_key_from_cid(peer_b.subkey_cid))
loop.run_until_complete(user_b.import_key_from_cid(peer_b.subkey_cid))
user_a.trust(peer_b, TrustLevel.TRUST_FULLY.value)
user_b.trust(peer_a, TrustLevel.TRUST_FULLY.value)

user_a_ping_request = PingRequestCall()
user_a_encrypted_call = user_a.encrypt_call(user_a_ping_request, peer_b)
user_a_message = IPRPCMessage(
    2, peer_b.subkey_cid, peer_a.subkey_cid, call=user_a_encrypted_call)
loop.run_until_complete(user_a_tx.send_message(user_a_message))

loop.run_until_complete(user_b_rx.get_messages())
for message in user_b_rx.messages:
    print("User B got a message:")
    print(message)

user_b_ping_reply = PingReplyCall()
user_b_encrypted_call = user_b.encrypt_call(user_b_ping_reply, peer_a)
user_b_message = IPRPCMessage(
    2, peer_a.subkey_cid, peer_b.subkey_cid, call=user_b_encrypted_call)
loop.run_until_complete(user_b_tx.send_message(user_b_message))

loop.run_until_complete(user_b_rx.get_messages())
for message in user_a_rx.messages:
    print("User A got a message:")
    print(message)

loop.run_until_complete(ipfs_instance_a.close())
loop.run_until_complete(ipfs_instance_b.close())

sys.exit(0)
