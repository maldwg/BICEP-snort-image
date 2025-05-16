from src.utils.models.ids_base import IDSParser, Alert
import json
import os
import os.path
from datetime import datetime
from ..utils.general_utilities import ANALYSIS_MODES
from dateutil import parser 
import re
class SnortParser(IDSParser):
    alert_file_location = "/opt/logs/alert_fast.txt"

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
                    print(e)
                    print("...skipping line...")
                    continue
                if parsed_alert:
                    parsed_lines.append(parsed_alert)
        open(self.alert_file_location, 'w').close()
        return parsed_lines      


    async def parse_line(self, line):
        parsed_line = Alert()
        try:
            # 1. Extract timestamp
            timestamp_match = re.search(r"\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+", line)
            if timestamp_match:
                raw_ts = timestamp_match.group()
                yy, mm, dd = raw_ts.split("/")[0], raw_ts.split("/")[1], raw_ts.split("/")[2].split("-")[0]
                time_part = raw_ts.split("-")[1]
                yyyy = await self.calculate_four_digit_year_from_two_digits(yy)
                formatted_ts = f"{yyyy}-{mm}-{dd} {time_part}"
                parsed_line.time = parser.parse(formatted_ts).replace(tzinfo=None).isoformat()

            # 2. Extract message (quoted string)
            msg_match = re.search(r"\[\d+:\d+:\d+\]\s+\"(.*?)\"", line)
            if msg_match:
                parsed_line.message = msg_match.group(1)

            # 3. Extract priority
            priority_match = re.search(r"\[Priority:\s*(\d+)\]", line)
            if priority_match:
                parsed_line.severity = await self.normalize_threat_levels(int(priority_match.group(1)))
            else: 
                parsed_line.severity = None

            # 4. Extract protocol and src -> dst 
            connection_match = re.search(
                r"\{(?P<proto>\w+)\}\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?\s+->\s+(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?",
                line
            )
            if connection_match:
                parsed_line.source_ip = connection_match.group("src_ip")
                parsed_line.source_port = connection_match.group("src_port")
                parsed_line.destination_ip = connection_match.group("dst_ip")
                parsed_line.destination_port = connection_match.group("dst_port")


            # 5. Extract type
            priority_match = re.search(r"\[Classification:\s*(.*?)\]", line)
            if priority_match:
                parsed_line.type = str(priority_match.group(1))
            else:
                parsed_line.type = "NA"
                
            # Optional: fallback if some essential data is missing
            if not parsed_line.time or not parsed_line.source_ip or not parsed_line.destination_ip or not parsed_line.source_port or not parsed_line.destination_port :
                return None
            
            return parsed_line

        except Exception as e:
            print(f"Could not parse line: {line.strip()} — {e}")
            return None
        
    
    
    
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