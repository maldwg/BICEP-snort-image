import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
from src.utils.models.ids_base import Alert
from src.models.snort_parser import SnortParser
import shutil
import json
import tempfile
from pathlib import Path
import os


TEST_FILE_LOCATION = "bicep-snort/src/tests/testfiles"

@pytest.fixture
def parser():
    parser = SnortParser()
    parser.alert_file_location = TEST_FILE_LOCATION
    return parser

@pytest.mark.asyncio
async def test_parse_alerts_empty_file(parser):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        parser.alert_file_location = temp_file.name
    alerts = await parser.parse_alerts()
    assert alerts == [], "Expected empty list for an empty log file"


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_data(parser: SnortParser):
    # pat to your file of outputted alerts. 
    # valid and invalid lines are expected as not every single line is to be expected to have all necessary information
    original_alert_file = f"{TEST_FILE_LOCATION}/alert_fast.txt"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/alert_fast_temporary.txt"
    shutil.copy(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    # there are 384 entries that should be regarded as valid
    assert len(alerts) == 14
    assert alerts[0].message == 'Potentially Bad Traffic'
    assert alerts[0].severity == 0.75
    assert alerts[10].message == 'Misc activity'
    assert alerts[10].severity == 0.5 

    os.remove(temporary_alert_file)



@pytest.mark.asyncio
async def test_parse_line_valid(parser: SnortParser):
    # original data
    line_data = '07/07-09:00:50.000000 [**] [1:254:17] "PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority" [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.10.3:53 -> 192.168.10.5:61968'
    alert = await parser.parse_line(line_data)
    assert isinstance(alert, Alert)
    assert alert.message == 'Potentially Bad Traffic'
    assert alert.severity == 0.75
    # If you have multiple types of alerts that you need to distinguish, add more tests like these

@pytest.mark.asyncio
async def test_parse_line_missing_fields(parser: SnortParser):
    # Missing dest_ip and dest_port
    line_data = '07/07-09:00:50.000000 [**] [1:254:17] "PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority" [**] [Classification: Potentially Bad Traffic] {UDP} 192.168.10.3 -> 192.168.10.5:61968'
    alert = await parser.parse_line(line_data)
    assert alert is None, "Expected None due to missing fields"


@pytest.mark.asyncio
async def test_normalize_threat_levels(parser: SnortParser):   
    assert await parser.normalize_threat_levels(1) == 1
    assert await parser.normalize_threat_levels(2) == 0.75
    assert await parser.normalize_threat_levels(3) == 0.5
    assert await parser.normalize_threat_levels(4) == 0.25
    assert await parser.normalize_threat_levels(5) is None
    assert await parser.normalize_threat_levels(None) is None
