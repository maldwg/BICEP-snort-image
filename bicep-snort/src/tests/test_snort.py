import pytest
import shutil
from unittest.mock import AsyncMock, patch, MagicMock
from src.models.snort import Snort
import os

@pytest.fixture(autouse=True, scope="session")
def set_env_variables():
    os.environ["SNORT_CONFIG_DIR"] = "/tmp/snort/configs/"
    os.environ["SNORT_DEFAULT_CONFIG_LOCATION"] = "/tmp/defautl.lua"

@pytest.fixture
def ids():
    ids = Snort()
    ids.container_id = 123
    ids.tap_interface_name = "tap123"
    ids.configuration_location = "my/config/location"
    ids.ruleset_location = "my/ruleset/location"
    ids.log_location = "my/log/location"
    return ids


@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.makedirs")
async def test_configure(mock_mkdir, mock_shutil, ids: Snort):
    mock_mkdir.return_value = None
    response = await ids.configure("/path/to/config.yaml")
    mock_shutil.assert_called_once_with("/path/to/config.yaml", ids.configuration_location)
    assert mock_mkdir.call_count == 2
    assert response == "succesfully configured"


@pytest.mark.asyncio
@patch("shutil.move")
async def test_configure_ruleset(mock_shutil, ids: Snort):
    response = await ids.configure_ruleset("/path/to/rules.rules")
    assert response == "succesfuly setup ruleset"


@pytest.mark.asyncio
@patch("src.models.snort.execute_command", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Snort):
    mock_execute_command.return_value = 555  
    pid = await ids.execute_network_analysis_command()
    mock_execute_command.assert_called_once_with([
       "snort", "-c", ids.default_configuration_location, "-i", ids.tap_interface_name, "-R", ids.ruleset_location, "-l", ids.log_location
    ])
    assert pid == 555



@pytest.mark.asyncio
@patch("src.models.snort.execute_command", new_callable=AsyncMock)
async def test_execute_static_analysis_command(mock_execute_command, ids: Snort):
    mock_execute_command.return_value = 777  
    dataset_path = "/path/to/capture.pcap"
    pid = await ids.execute_static_analysis_command(dataset_path)
    mock_execute_command.assert_called_once_with([
        "snort", "-c", ids.default_configuration_location, "-R", ids.ruleset_location,  "-r", dataset_path, "-l", ids.log_location
    ])
    assert pid == 777


def test_get_additional_config_directory_from_file_location(ids: Snort):
    ids.configuration_location = "/my/config/location/file.extension"
    config_dir = ids.get_additional_config_directory_from_file_location()
    print(config_dir)
    assert config_dir == "/my/config/location/"