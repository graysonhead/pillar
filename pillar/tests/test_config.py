from unittest import TestCase
import os
import yaml
from ..config import Config, ConfigOption, UNSET, OptionNotValid


class TestConfigOptions(TestCase):

    def setUp(self) -> None:
        self.option = ConfigOption(
            'test',
            [str],
            default_value='test_value',
            description="A test attribute",
        )

    def test_option_attributes(self):
        self.assertEqual('test', self.option.attribute)
        self.assertEqual([str], self.option.valid_types)
        self.assertEqual('test_value', self.option.default_value)
        self.assertEqual('A test attribute', self.option.description)
        self.assertEqual('test_value', self.option.example)

    def test_option_set_incorrect_value(self):
        with self.assertRaises(TypeError):
            self.option.set(value=123)

    def test_option_set_value(self):
        self.option.set(value='test_value_2')
        self.assertEqual('test_value_2', self.option.value)

    def test_option_set_default_value(self):
        self.option.set()
        self.assertEqual('test_value', self.option.get())

    def test_option_value_unset_when_initialized(self):
        self.assertEqual(UNSET, self.option.value)

    def test_option_get_default_value_when_unset(self):
        self.assertEqual('test_value', self.option.get())

    def test_option_example(self):
        new_option = ConfigOption(
            'test',
            [str],
            default_value='test_value',
            description="A test attribute",
            example='This is an example'
        )
        self.assertEqual('This is an example', new_option.example)


test_options = [ConfigOption('test_option',
                             [str],
                             default_value='default_value',
                             description='This is an option')]


class TestConfig(TestCase):

    def setUp(self) -> None:
        self.original_options = Config.options
        Config.options = [ConfigOption('test_option',
                                       [str],
                                       default_value='default_value',
                                       description='This is an option')]
        self.config = Config(test_option='a_value')

    def tearDown(self) -> None:
        Config.options = self.original_options

    def test_set_invalid_option(self):
        with self.assertRaises(OptionNotValid):
            self.config.set_value('invalid_value', None)

    def test_set_valid_config_option(self):
        self.config.set_value('test_option', 'value')
        result = self.config.get_value('test_option')
        self.assertEqual('value', result)

    def test_get_config_dict(self):
        result = self.config.get_dict()
        self.assertEqual({'test_option': 'a_value'}, result)


class TestEmptyConfig(TestCase):

    def setUp(self) -> None:
        self.original_options = Config.options
        Config.options = [ConfigOption('test_option',
                                       [str],
                                       default_value='default_value',
                                       description='This is an option')]
        self.config = Config()

    def tearDown(self) -> None:
        Config.options = self.original_options

    def test_get_empty_option_returns_default_value(self):
        result = self.config.get_value('test_option')
        self.assertEqual('default_value', result)


class TestConfigLoadFromFile(TestCase):

    def setUp(self) -> None:
        self.original_options = Config.options
        Config.options = [ConfigOption('test_option',
                                       [str],
                                       default_value='default_value',
                                       description='This is an option')]
        self.config = Config.load_from_yaml(os.path.join(os.path.dirname(
            os.path.abspath(__file__)
        ), 'data/config.yaml'))

    def tearDown(self) -> None:
        Config.options = self.original_options

    def test_value_set_from_yaml(self):
        result = self.config.get_value('test_option')
        self.assertEqual('value_from_yaml', result)


class TestConfigWriteDefaultOptions(TestCase):

    def setUp(self) -> None:
        self.original_options = Config.options
        Config.options = [ConfigOption('test_option',
                                       [str],
                                       default_value='default_value',
                                       description='This is an option')]
        self.config = Config(test_option='a_value')
        self.file_path = os.path.join(os.getcwd(), 'testconfig.yaml')

    def tearDown(self) -> None:
        Config.options = self.original_options
        os.remove(self.file_path)

    def test_write_defaults_to_file(self):
        self.config.generate_default(self.file_path)
        with open(self.file_path, 'r') as file:
            result = yaml.load(file, Loader=yaml.FullLoader)

        self.assertEqual({'test_option': 'default_value'}, result)
