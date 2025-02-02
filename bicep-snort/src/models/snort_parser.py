from src.utils.models.ids_base import IDSParser, Alert
import json
import os
import os.path
from datetime import datetime
from ..utils.general_utilities import ANALYSIS_MODES
from dateutil import parser 
import re
class SnortParser(IDSParser):

    # TODO: 11 scrape the whole directory  
    alert_file_location = "/opt/logs/alert_fast.txt"
    LOG_PATTERN = re.compile(
        r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+) \[\*\*\] \[\d+:\d+:\d+\] \"(.*?)\" \[\*\*\] \[Classification: (.*?)\] \[Priority: (\d+)\] \{(\w+)\} (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)? -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)?"
    )

    async def parse_alerts(self):
        parsed_lines = []
        if not os.path.isfile(self.alert_file_location):
            return parsed_lines
        with open(self.alert_file_location, "r") as file:
            for line in file:
                try:
                    parsed_alert = await self.parse_line(line)
                except Exception as e:
                    print(f"Could not parse line {line}")
                    print("...skipping line...")
                if parsed_alert:
                    parsed_lines.append(parsed_alert)
        open(self.alert_file_location, 'w').close()
        return parsed_lines      



    async def parse_line(self, line):
        match = self.LOG_PATTERN.match(line)
        if not match:
            return None

        parsed_line = Alert()
        timestamp, event_type, classification, priority, protocol, src_ip, src_port, dest_ip, dest_port = match.groups()

        parsed_line.time = parser.parse(timestamp).replace(tzinfo=None).isoformat()
        parsed_line.source_ip = src_ip
        parsed_line.source_port = str(src_port) if src_port else None
        parsed_line.destination_ip = dest_ip
        parsed_line.destination_port = str(dest_port) if dest_port else None
        parsed_line.severity = await self.normalize_threat_levels(int(priority))
        parsed_line.message = classification

        return parsed_line
    
    
    async def normalize_threat_levels(self, threat: int):
        # Snort got 4 threat levels with 1 being the highest and 4 the lowest
        if threat is None or threat < 1 or threat > 4:
            return None
        return 1 - ((threat - 1) / 4)