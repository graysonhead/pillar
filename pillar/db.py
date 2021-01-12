from sqlalchemy import create_engine, \
    Column, \
    Integer, \
    String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import Config
from .IPRPC.channel import IPRPCChannel
import logging

Base = declarative_base()


class Channel(Base):
    __tablename__ = 'channels'
    id = Column(Integer, primary_key=True)
    queue_id = Column(String(120))


class PillarDB:
    """
    This class generates new sessions with the get_session() method
    """

    def __init__(self, config: Config):
        self.engine = self._get_engine(
            f"sqlite:///{config.get_value('db_path')}")
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
