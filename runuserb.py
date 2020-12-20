from src.pillar.user import MyUser, PeerUser
from src.pillar.config import Config
from src.pillar.community import Community
import asyncio

if __name__ == "__main__":

    config = Config()
    user = MyUser()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(user._init(name_real="fakeuser",
                                       name_comment="notreal",
                                       name_email="test@example.com"))

    print(user.name)
    print(user.fingerprint)
    print(user.pubkey_cid)

    peer = PeerUser('QmVbj2fDoKERF7VDn6Yrz4xwKvr3VBPZrcECefUVg1AoSH')
    community = Community("45987435uh45sdfjhber8374t238gryg")
    
    loop.run_until_complete(community.send_message(user.pubkey_cid, spencer.pubkey_cid, user.pubkey_cid))

    
