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
        r"(\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+) \[\*\*\] \[\d+:\d+:\d+\] \"(.*?)\" \[\*\*\] \[Classification: (.*?)\] \[Priority: (\d+)\] \{(\w+)\} (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)? -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)?"    
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


    # hw to treat null values ? where allowed?

    async def parse_line(self, line):
        match = self.LOG_PATTERN.match(line)
        if not match:
            return None
        parsed_line = Alert()
        timestamp, message, category, priority, protocol, src_ip, src_port, dest_ip, dest_port = match.groups()
        try:
            # timestamp = 25/07/30-hours:minutes:seconds.milisenconds
            yy = timestamp.split("/", 2)[0]
            mm = timestamp.split("/", 2)[1]
            dd = timestamp.split("/", 2)[2].split("-")[0]
            time_part = timestamp.split("-")[1]
            yyyy = await self.calculate_four_digit_year_from_two_digits(yy)
            formatted_timestamp = f"{yyyy}-{mm}-{dd} {time_part}"
            parsed_line.time = parser.parse(formatted_timestamp).replace(tzinfo=None).isoformat()
            
            parsed_line.source_ip = src_ip
            parsed_line.source_port = str(src_port) if src_port else None
            parsed_line.destination_ip = dest_ip
            parsed_line.destination_port = str(dest_port) if dest_port else None
            parsed_line.severity = await self.normalize_threat_levels(int(priority))
            parsed_line.message = message
            parsed_line.type = category
        except:
            print("Could not manage to parse line")
            return None

        if not parsed_line.time or not parsed_line.source_ip or not parsed_line.source_port or not parsed_line.destination_ip or not parsed_line.destination_port or not parsed_line:
            return None
        
        return parsed_line
    
    
    async def normalize_threat_levels(self, threat: int):
        # Snort got 4 threat levels with 1 being the highest and 4 the lowest
        if threat is None or threat < 1 or threat > 4:
            return None
        return 1 - ((threat - 1) / 4)
    
    async def calculate_four_digit_year_from_two_digits(self, yy):
        current_year = datetime.now().year
        current_century = current_year // 100 * 100  # 1900 or 2000
        last_two_digits_of_current_year = current_year % 100
        if int(yy) > last_two_digits_of_current_year:
            yyyy = current_century - 100 + int(yy)  # Assume 1900s
        else:
            yyyy = current_century + int(yy)  # Assume 2000s
        return yyyy