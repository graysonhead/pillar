from sqlalchemy import create_engine, \
    Column, \
    Integer, \
    String, \
    BLOB, \
    ForeignKey
from .multiproc import PillarThreadMethodsRegister, \
    PillarThreadMixIn, \
    PillarWorkerThread, \
    MixedClass
from sqlalchemy_utils.functions import database_exists
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.orm.properties import ColumnProperty
from .config import PillardConfig
from pgpy import PGPKeyring, PGPKey
from contextlib import contextmanager
from pathos.helpers import mp as pmp
import logging

pillar_db_register = PillarThreadMethodsRegister()


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


class PrimaryIdentity(Base):
    __tablename__ = "primary_identities"
    public_key_cid = Column(String, primary_key=True)
    fingerprint = Column(String)


class NodeIdentity(Base):
    __tablename__ = "node_identities"
    id = Column(Integer, primary_key=True)
    public_key_cid = Column(String)
    fingerprint = Column(String)
    fingerprint_cid = Column(String)


class Invitation(Base):
    __tablename__ = 'invitations'
    id = Column(Integer, primary_key=True)
    key = relationship("Key", uselist=False, back_populates='invitation')


class KeyManagerData(Base):
    __tablename__ = 'key_manager'
    node_uuid = Column(String, primary_key=True)
    user_primary_key_cid = Column(String)


class PillarDB:
    """
    This class generates new sessions with the get_session() method
    """

    def __init__(self, config: PillardConfig):
        self.db_uri = self._get_sqlite_uri(config.get_value('db_path'))
        self.engine = self._get_engine(self.db_uri)
        self.session_constructor = sessionmaker(bind=self.engine)

    def _get_sqlite_uri(self, path: str):
        absolute_path = path
        return f"sqlite:///{absolute_path}"

    def _get_engine(self, uri: str):
        return create_engine(uri, connect_args={'check_same_thread': False})

    def get_session(self):
        return self.session_constructor()


class PillarDataStore:

    def __init__(self, config: PillardConfig):
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
        session = self.get_session()
        try:
            session.add(model_instance)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

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
        finally:
            session.close()

    def get_keys(self) -> list:
        session = self.get_session()
        keys = session.query(Key).all()
        deserialized_keys = []
        for key in keys:
            deserialized_key, other = PGPKey.from_blob(key.key)
            deserialized_keys.append(deserialized_key)
        return deserialized_keys

    def load_model_instance(self, model_class, filter_attribs):
        session = self.get_session()
        result = session.query(model_class).filter(**filter_attribs).one()
        session.close()
        return result

    def load_model_instances(self, model_class) -> list:
        session = self.get_session()
        try:
            return session.query(model_class).all()
        finally:
            session.close()

    def reinitialize_database(self):
        self.logger.info("Deleting database:")
        for tbl in reversed(Base.metadata.sorted_tables):
            self.logger.info(f"Deleted table {tbl}")
            self.pdb.engine.execute(tbl.delete())
        self.create_database()


class PillarDBWorker(PillarWorkerThread):
    """
    This class generates new sessions with the get_session() method
    """
    methods_register = pillar_db_register

    def __init__(self,
                 config: PillardConfig,
                 command_queue: pmp.Queue,
                 output_queue: pmp.Queue):
        self.db_uri = self._get_sqlite_uri(config.get_value('db_path'))
        self.engine = self._get_engine(self.db_uri)
        self.session_constructor = sessionmaker(bind=self.engine)
        super().__init__(command_queue=command_queue,
                         output_queue=output_queue)

    def _get_sqlite_uri(self, path: str):
        absolute_path = path
        return f"sqlite:///{absolute_path}"

    def _get_engine(self, uri: str):
        return create_engine(uri, connect_args={"check_same_thread": False})

    def get_session(self):
        return self.session_constructor()

    @contextmanager
    def get_scoped_session(self):
        session = self.get_session()
        try:
            yield session
            session.commit()
        except:  # noqa E772
            session.rollback()
            raise
        finally:
            session.close()

    @pillar_db_register.register_method
    def add_item(self, item):
        with self.get_scoped_session() as session:
            session.merge(item)

    @pillar_db_register.register_method
    def get_all(self, model, expunge: bool = True):
        with self.get_scoped_session() as session:
            records = session.query(model).all()
            session.expunge_all()
            return records

    @pillar_db_register.register_method
    def save_key(self, key: PGPKey):
        with self.get_scoped_session() as session:
            self.logger.info(f"Storing key {key.fingerprint} in database")
            key_item = Key(fingerprint=key.fingerprint, key=bytes(key))
            session.add(key_item)


class DBMixIn(PillarThreadMixIn):
    queue_thread_class = PillarDBWorker
    interface_name = "db"


class DBInterface(DBMixIn,
                  metaclass=MixedClass):
    pass


class PillarDBObject:
    model = None

    def __init__(self, command_queue: pmp.Queue, output_queue: pmp.Queue):
        self.command_queue = command_queue
        self.output_queue = output_queue
        self.db_interface = self.get_db_interface()
        if not getattr(self, 'logger', None):
            self.logger = logging.getLogger(str(self))

    def get_db_interface(self):
        return DBInterface(str(self),
                           command_queue=self.command_queue,
                           output_queue=self.output_queue)

    def _pds_generate_model(self):
        attribute_dict = {}
        for attrib in self._pds_get_attributes():
            attribute_dict.update(
                {attrib.name: getattr(self, attrib.name)})
        return self.model(**attribute_dict)

    @classmethod
    def _pds_get_attributes(cls):
        attribs = []
        for attrib_name in dir(cls.model):
            attribute = getattr(cls.model, attrib_name)
            if isinstance(attribute, InstrumentedAttribute):
                if isinstance(attribute.prop, ColumnProperty):
                    attribs.append(attribute)
        return attribs

    def pds_save(self):
        self.logger.info(f"Saving {self} to database.")
        model_instance = self._pds_generate_model()
        self.db_interface.db.add_item(model_instance)

    @classmethod
    def _load_model_instances_from_db(cls,
                                      command_queue: pmp.Queue,
                                      output_queue: pmp.Queue,
                                      expunge: bool = True,
                                      return_interface=False):
        temp_interface = DBInterface(cls.__name__,
                                     command_queue=command_queue,
                                     output_queue=output_queue)
        model_instance = temp_interface.db.get_all(cls.model, expunge=expunge)
        if not return_interface:
            return model_instance
        else:
            return model_instance, temp_interface

    @classmethod
    def get_instance_from_model(cls, model,
                                init_args: list = None,
                                init_kwargs: dict = None):
        if init_args and init_kwargs:
            instance = cls(*init_args, **init_kwargs)
        elif init_args:
            instance = cls(*init_args)
        elif init_kwargs:
            instance = cls(**init_kwargs)
        else:
            instance = cls()

        for attrib in cls._pds_get_attributes():
            setattr(instance, attrib.name, getattr(model, attrib.name))
        return instance

    @classmethod
    def load_all_from_db(cls,
                         command_queue: pmp.Queue,
                         output_queue: pmp.Queue,
                         init_args: list = None,
                         init_kwargs: dict = None,
                         expunge: bool = True,):
        instance_list = []
        for model in cls._load_model_instances_from_db(command_queue,
                                                       output_queue,
                                                       expunge=expunge):
            instance_list.append(cls.get_instance_from_model(
                model,
                init_args=init_args,
                init_kwargs=init_kwargs)
            )
        return instance_list
