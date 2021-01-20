from sqlalchemy import create_engine, \
    Column, \
    Integer, \
    String, \
    BLOB, \
    ForeignKey
from sqlalchemy_utils.functions import database_exists
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.orm.properties import ColumnProperty
from .config import Config
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
    invitation_id = Column(Integer, ForeignKey('invitations.id'))
    invitation = relationship("Invitation", back_populates='key')


class Invitation(Base):
    __tablename__ = 'invitations'
    id = Column(Integer, primary_key=True)
    key = relationship("Key", uselist=False, back_populates='invitation')


class PillarDB:
    """
    This class generates new sessions with the get_session() method
    """

    def __init__(self, config: Config):
        self.db_uri = self._get_sqlite_uri(config.get_value('db_path'))
        self.engine = self._get_engine(self.db_uri)
        self.session_constructor = sessionmaker(bind=self.engine)

    def _get_sqlite_uri(self, path: str):
        absolute_path = path
        return f"sqlite:///{absolute_path}"

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

    def store_instance(self, model_instance):
        with self.get_session() as session:
            try:
                session.add(model_instance)
                session.commit()
            except Exception as e:
                session.rollback()
                raise e

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

    def load_model_instance(self, model_class, filter_attribs):
        with self.get_session() as session:
            return session.query(model_class).filter(**filter_attribs).one()

    def reinitialize_database(self):
        self.logger.info("Deleting database:")
        for tbl in reversed(Base.metadata.sorted_tables):
            self.logger.info(f"Deleted table {tbl}")
            self.pdb.engine.execute(tbl.delete())
        self.create_database()


class PillarDatastoreMixIn:
    model = None

    def _pds_get_model_instance(self):
        attribute_dict = {}
        for attrib in self._pds_get_attributes():
            attribute_dict.update(
                {attrib.name: getattr(self, attrib.name)})
        return self.model(**attribute_dict)

    def _pds_get_attributes(self):
        attribs = []
        for attrib_name in dir(self.model):
            attribute = getattr(self.model, attrib_name)
            if isinstance(attribute, InstrumentedAttribute):
                if isinstance(attribute.prop, ColumnProperty):
                    attribs.append(attribute)
        return attribs

    def pds_save(self, pds: PillarDataStore):
        model_instance = self._pds_get_model_instance()
        pds.store_instance(model_instance)
