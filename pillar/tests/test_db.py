from ..db import PillarDBWorker, PillarDBObject
from ..config import PillardConfig
from unittest import TestCase
from unittest.mock import patch, MagicMock
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
import multiprocessing as mp


class TestPillarDB(TestCase):

    @patch.object(PillarDBWorker, '_get_engine')
    def test_engine_creation(self, mock_func):
        config = PillardConfig()
        manager = mp.Manager()
        command_queue = manager.Queue()
        output_queue = manager.Queue()
        db = PillarDBWorker(config, command_queue, output_queue)
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


class TestClass(PillarDBObject):
    model = TestModel

    def __init__(self,
                 *args,
                 id: int = None,
                 test_int: int = None,
                 test_str: str = '',
                 unrelated_attrib: str = '',
                 **kwargs):
        self.id = id
        self.test_int = test_int
        self.test_str = test_str
        self.unrelated_attrib = unrelated_attrib
        self.args = args
        self.kwargs = kwargs
        super().__init__(MagicMock(), MagicMock())


class TestParentClass(PillarDBObject):
    model = TestParent

    def __init__(self, id: int = None,
                 some_string: str = '',
                 command_queue=None,
                 output_queue=None):
        self.id = id
        self.some_string = some_string
        super().__init__(command_queue, output_queue)


class TestPillarDBObject(TestCase):

    def setUp(self) -> None:
        self.test_args = {"test_int": 4,
                          "test_str": "hi",
                          "unrelated_attrib": "yo"}
        self.test_class = TestClass(**self.test_args)
        self.test_class.db_interface.db = MagicMock()
        self.pds = MagicMock()

    def test_generate_model_instance(self):
        model_object = self.test_class._pds_generate_model()
        self.assertEqual(TestModel, type(model_object))
        self.assertEqual(4, model_object.test_int)
        with self.assertRaises(AttributeError):
            model_object.unrelated_attrib

    def test_pds_save(self):
        self.test_class.pds_save()
        self.test_class.db_interface.db.add_item.assert_called()

    @patch('pillar.db.DBInterface')
    def test_load_instances_from_db(self, mocked_interface):
        instance, interface = TestClass.\
            _load_model_instances_from_db(MagicMock(),
                                          MagicMock(),
                                          return_interface=True)
        interface.db.get_all.assert_called()

    @patch('pillar.db.DBInterface')
    def test_load_all_from_db_empty_no_models(self, patched_class):
        result = TestClass.load_all_from_db(MagicMock(), MagicMock())
        self.assertEqual([], result)

    def test_load_instance_from_model_no_args(self):
        model = TestModel(id=1, test_str="Hello", test_int=1234)
        instance = TestClass.get_instance_from_model(model)
        self.assertEqual(1, instance.id)
        self.assertEqual("Hello", instance.test_str)
        self.assertEqual(1234, instance.test_int)

    def test_load_instance_from_model_both_args(self):
        model = TestModel(id=1, test_str="Hello", test_int=1234)
        args = ["Test_arg"]
        kwargs = {"arg1": "hi"}
        instance = TestClass.get_instance_from_model(model,
                                                     init_args=args,
                                                     init_kwargs=kwargs)
        self.assertIn(args[0], instance.args)
        self.assertEqual(kwargs, instance.kwargs)


class TestPillarDatastoreMixInRelationships(TestCase):

    def setUp(self) -> None:
        self.test_parent = TestParentClass(some_string="hello",
                                           command_queue=MagicMock(),
                                           output_queue=MagicMock())
        self.pds = MagicMock()

    def test_pds_save(self):
        model_object = self.test_parent._pds_generate_model()
        self.assertEqual("hello", model_object.some_string)
