from sqlalchemy import create_engine, \
    Column, \
    Integer, \
    String, \
    BLOB
from sqlalchemy_utils.functions import database_exists
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import Config
from .IPRPC.channel import IPRPCChannel
from pgpy import PGPKeyring, PGPKey
import logging

Base = declarative_base()


class DatabaseExists(Exception):
    pass


class Channel(Base):
    __tablename__ = 'channels'
    id = Column(Integer, primary_key=True)
    queue_id = Column(String(120))


class Key(Base):
    __tablename__ = 'keys'
    fingerprint = Column(String(120), primary_key=True)
    key = Column(BLOB())


class PillarDB:
    """
    This class generates new sessions with the get_session() method
    """

    def __init__(self, config: Config):
        self.db_uri = config.get_value('db_uri')
        self.engine = self._get_engine(self.db_uri)
        self.session_constructor = sessionmaker(bind=self.engine)

    def _get_engine(self, uri: str):
        return create_engine(uri)

    def get_session(self):
        return self.session_constructor()


class PillarDataStore:

    def __init__(self, config: Config):
        self.pdb = PillarDB(config)
        self.logger = logging.getLogger(self.__repr__())

    def get_session(self):
        return self.pdb.get_session()

    def database_exists(self):
        return database_exists(self.pdb.db_uri)

    def create_database(self, purge: bool = False):
        self.logger.info("Creating database")
        if not purge:
            Base.metadata.create_all(self.pdb.engine)
        else:
            if self.database_exists():
                self.reinitialize_database()
            else:
                self.create_database()

    def store_keyring(self, keyring: PGPKeyring):
        session = self.get_session()
        try:
            for fingerprint in keyring.fingerprints():
                with keyring.key(fingerprint) as key:
                    self.add_key(key, session)
                    self.logger.info(
                        f"Storing key {key.fingerprint} in database")
                    key_item = Key(fingerprint=key.fingerprint, key=bytes(key))
                    session.add(key_item)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e

    def save_key(self, key: PGPKey,):
        session = self.get_session()
        try:
            self.logger.info(f"Storing key {key.fingerprint} in database")
            key_item = Key(fingerprint=key.fingerprint, key=bytes(key))
            session.add(key_item)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e

    def get_keys(self) -> list:
        session = self.get_session()
        keys = session.query(Key).all()
        deserialized_keys = []
        for key in keys:
            deserialized_key, other = PGPKey.from_blob(key.key)
            deserialized_keys.append(deserialized_key)
        return deserialized_keys

    def reinitialize_database(self):
        self.logger.info("Deleting database:")
        for tbl in reversed(Base.metadata.sorted_tables):
            self.logger.info(f"Deleted table {tbl}")
            self.pdb.engine.execute(tbl.delete())
        self.create_database()

    def add_channel(self, channel: IPRPCChannel):
        new_row = Channel(queue_id=channel.queue_id)
        session = self.get_session()
        try:
            session.add(new_row)
            session.commit()
        except Exception as e:
            self.logger.error(f"Could not add channel to datastore: {e}")
            session.rollback()

    def get_channels(self) -> list:
        session = self.get_session()
        try:
            return session.query(Channel).all()
        except Exception as e:
            self.logger.error(f"Could not get list of channels from "
                              f"datastore: {e}")
