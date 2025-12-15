import asyncio
from  src.utils.models.ids_base import IDSBase
import shutil
import os
from ..utils.general_utilities import execute_command_async
from .snort_parser import SnortParser

class Snort(IDSBase):
    # default config injected in dockerfile
    default_configuration_location: str = os.getenv("SNORT_DEFAULT_CONFIG_LOCATION", "/etc/snort/etc/snort/snort.lua")
    configuration_location: str = "/tmp/configuration/configuration.lua"
    log_location: str = "/opt/logs"
    ruleset_location: str = "/tmp/custom_rules.rules"
    so_rules_path: str = f"{"/".join(default_configuration_location.split("/")[:-2])}/so_rules/"
    snort_extras_path: str = "/usr/local/snort/lib/snort/plugins/extra"
    parser = SnortParser()
    parser.alert_file_location = f"{log_location}/alert_fast.txt"

    async def configure(self, file_path):
        # Set env variable for the additional configs to be included by the default configuration
        additional_config_dir = self.get_additional_config_directory_from_file_location()
        os.environ["SNORT_CONFIG_DIR"] = additional_config_dir
        try:            
            os.makedirs(self.log_location, exist_ok=True)
            os.makedirs(additional_config_dir, exist_ok=True)
            shutil.move(file_path, self.configuration_location)
            return "succesfully configured"
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Exception occured occured while configuring suricata. Please check the confgiuration file again and make sure it is valid!",
            )
    
    async def configure_ruleset(self, file_path):
        shutil.move(file_path, self.ruleset_location)
        return "succesfuly setup ruleset"

    async def execute_network_analysis_command(self):
        # use the default-config path, go one directory up, and in the so_rules section, where the lightspd so_rules reside (/etc/snort/etc/so_rules)
        command = ["snort","-c", self.default_configuration_location, "-i", self.tap_interface_name, "-R", self.ruleset_location, "-l", self.log_location, "--plugin-path", self.so_rules_path,"--plugin-path", self.snort_extras_path]
        pid = await execute_command_async(command)
        return pid
    
    async def execute_static_analysis_command(self, file_path):
        # use the default-config path, go one directory up, and in the so_rules section, where the lightspd so_rules reside (/etc/snort/etc/so_rules)
        command = ["snort","-c", self.default_configuration_location, "-R", self.ruleset_location,  "-r", file_path, "-l", self.log_location, "--plugin-path", self.so_rules_path, "--plugin-path", self.snort_extras_path]
        pid = await execute_command_async(command)
        return pid
    
    def get_additional_config_directory_from_file_location(self):
        config_directory = "/".join(self.configuration_location.split("/")[:-1]) + "/" # add trailing slash, do not delete it, otherwise default config will have troubles
        return config_directory
    