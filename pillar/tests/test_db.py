from ..db import PillarDBWorker, PillarDatastoreMixIn
from ..config import Config
from unittest import TestCase
from unittest.mock import patch, MagicMock
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship


class TestPillarDB(TestCase):

    @patch.object(PillarDBWorker, '_get_engine')
    def test_engine_creation(self, mock_func):
        config = Config()
        db = PillarDBWorker(config)
        db._get_engine('sqlite:///:memory:')
        mock_func.assert_called_with('sqlite:///:memory:')


TestBase = declarative_base()


class TestModel(TestBase):
    __tablename__ = 'testmodel'
    id = Column(Integer, primary_key=True)
    test_int = Column(Integer)
    test_str = Column(String(120))


class TestParent(TestBase):
    __tablename__ = 'parent'
    id = Column(Integer, primary_key=True)
    child = relationship("TestChild", uselist=False, back_populates="parent")
    some_string = Column(String(120))


class TestChild(TestBase):
    __tablename__ = 'child'
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey('parent.id'))
    parent = relationship("TestParent", back_populates="child")
    some_other_string = Column(String(120))


class TestClass(PillarDatastoreMixIn):
    model = TestModel

    def __init__(self,
                 id: int = None,
                 test_int: int = None,
                 test_str: str = '',
                 unrelated_attrib: str = ''):
        self.id = id
        self.test_int = test_int
        self.test_str = test_str
        self.unrelated_attrib = unrelated_attrib
        super().__init__()


class TestParentClass(PillarDatastoreMixIn):
    model = TestParent

    def __init__(self, id: int = None,
                 some_string: str = ''):
        self.id = id
        self.some_string = some_string
        super().__init__()


class TestPillarDatastoreMixIn(TestCase):

    def setUp(self) -> None:
        self.test_args = {"test_int": 4,
                          "test_str": "hi",
                          "unrelated_attrib": "yo"}
        self.test_class = TestClass(**self.test_args)
        self.test_class.pillar_db = MagicMock()
        self.pds = MagicMock()

    def test_generate_model_instance(self):
        model_object = self.test_class._pds_generate_model()
        self.assertEqual(TestModel, type(model_object))
        self.assertEqual(4, model_object.test_int)
        with self.assertRaises(AttributeError):
            model_object.unrelated_attrib

    def test_pds_save(self):
        self.test_class.pds_save()
        self.test_class.pillar_db.add_item.assert_called()


class TestPillarDatastoreMixInRelationships(TestCase):

    def setUp(self) -> None:
        self.test_parent = TestParentClass(some_string="hello")
        self.pds = MagicMock()

    def test_pds_save(self):
        model_object = self.test_parent._pds_generate_model()
        self.assertEqual("hello", model_object.some_string)
