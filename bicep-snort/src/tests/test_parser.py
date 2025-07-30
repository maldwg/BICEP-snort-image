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
    # valid and invalid lines are expected as not every single line is to be expected to have all necessary information
    original_alert_file = f"{TEST_FILE_LOCATION}/alert_fast.txt"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/alert_fast_temporary.txt"
    shutil.copy(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    print(parser.alert_file_location)
    alerts: list[Alert] = await parser.parse_alerts()
    
    assert len(alerts) == 18
    alerts = sorted(alerts, key=lambda alert: (alert.time, alert.source_ip))
    print(alerts[0])
    print(alerts[10])
    assert alerts[0].message == '(http_inspect) partial start line'
    assert alerts[0].severity == 0.5
    assert alerts[10].type == 'Detection of a Network Scan'
    assert alerts[10].severity == 0.5

    os.remove(temporary_alert_file)



@pytest.mark.asyncio
async def test_parse_line_valid(parser: SnortParser):
    # original data
    line_data = '17/07/06-09:01:32.000000 [**] [1:1917:16] "INDICATOR-SCAN UPnP service discover attempt" [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 192.168.10.15:63176 -> 239.255.255.250:1900'
    alert = await parser.parse_line(line_data)
    print(alert)
    assert isinstance(alert, Alert)
    assert alert.message == 'INDICATOR-SCAN UPnP service discover attempt'
    assert alert.severity == 0.5


@pytest.mark.asyncio
async def test_parse_line_valid(parser: SnortParser):
    # original data
    line_data = '11/08/17-14:10:28.422005 [**] [119:284:1] "(http_inspect) partial start line" [**] [Priority: 3] {TCP} 147.32.84.165:1349 -> 81.10.0.18:6667'
    alert = await parser.parse_line(line_data)
    print(alert.message)
    assert isinstance(alert, Alert)
    assert alert.message == '(http_inspect) partial start line'
    assert alert.severity == 0.5

@pytest.mark.asyncio
async def test_parse_line_missing_fields(parser: SnortParser):
    # Missing dest_ip and dest_port
    line_data = '17/07/06-09:01:32.000000 [**] [1:1917:16] "INDICATOR-SCAN UPnP service discover attempt" [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 192.168.10.15 -> 239.255.255.250'
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
