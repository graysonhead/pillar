from unittest import TestCase
import os
import yaml
from ..config import Config


class TestConfig(TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'data/config.yaml')
        with open(self.path, 'r') as f:
            self.file_data = yaml.load(f, Loader=yaml.FullLoader)

        self.config = Config(path=self.path)

    def test_load_file(self):
        self.assertEqual(os.path.isfile(self.path), True)
        for attrib in Config.option_attribs:
            self.assertEqual(self.file_data[attrib],
                             getattr(self.config, attrib))

    def test_save(self):
        savefile = os.path.join(os.getcwd(), 'testconfig.yaml')
        self.config.save(path=savefile)
        with open(savefile, 'r') as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
            for attrib in Config.option_attribs:
                self.assertEqual(data[attrib],
                                 getattr(self.config, attrib))
