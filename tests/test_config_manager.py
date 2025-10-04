import pytest
import logging
from config_manager import ConfigManager


class TestConfigManager:

    @pytest.fixture
    def config_manager(self):
        return ConfigManager()

    @pytest.fixture
    def logger_name(self):
        return 'config_manager'

    def test_setup_logging(self, config_manager, logger_name):
        config_manager_logger = config_manager.setup_logging()
        assert isinstance(config_manager_logger, logging.Logger)
        assert config_manager_logger.name == logger_name

    @pytest.mark.parametrize(
        'method_name, expected_log_msg',
        (
            ('detect_threats', 'Threat detection logic executed.'),
            ('protect_system', 'System protection measures applied.'),
            ('respond_to_incidents', 'Incident response executed.'),
            ('update_config', 'Configuration updated successfully.'),
        ),
    )
    def test_update_config_methods(self, config_manager, logger_name, method_name, expected_log_msg, caplog):
        caplog.clear()
        with caplog.at_level(level=logging.INFO, logger=logger_name):
            getattr(config_manager, method_name)(config={'sample': True})

        assert any(
            rec.levelno == logging.INFO and expected_log_msg in rec.message
            for rec in caplog.records
        )

    def test_update_config_exception(self, config_manager, logger_name, monkeypatch, caplog):
        def raise_exception(self, config):
            raise AttributeError('error message')

        monkeypatch.setattr(
            target=ConfigManager,
            name='detect_threats',
            value=raise_exception
        )

        caplog.clear()
        with caplog.at_level(level=logging.ERROR, logger=logger_name):
            config_manager.update_config(config={'k': 'v'})

        assert any(
            rec.levelno == logging.ERROR and 'Error updating configuration: error message' in rec.message
            for rec in caplog.records
        )
