from OperatingSystem import OperatingSystem
from SQLiteDatabase import SQLiteDatabase


class UnsupportedOSException(Exception):
    pass


class WazuhAgent:
    def __init__(self, agent_dict: dict, sqlite_filename: str) -> None:
        self.sqlite_filename = sqlite_filename
        self.parse_agent_dict(agent_dict=agent_dict)
        self.get_end_of_life_date_from_database()

    def parse_agent_dict(self, agent_dict: dict):
        self.OS = OperatingSystem(os_dict=agent_dict["os"])
        self.version = agent_dict.get("version", None)
        self.id = agent_dict.get("id", None)
        self.dateAdd = agent_dict.get("dateAdd", None)
        self.lastKeepAlive = agent_dict.get("lastKeepAlive", None)
        self.mergedSum = agent_dict.get("mergedSum", None)
        self.manager = agent_dict.get("manager", None)
        self.group = agent_dict.get("group", None)
        self.node_name = agent_dict.get("node_name", None)
        self.ip = agent_dict.get("ip", None)
        self.group_config_status = agent_dict.get("group_config_status", None)
        self.status_code = agent_dict.get("status_code", None)
        self.status = agent_dict.get("status", None)
        self.registerIP = agent_dict.get("registerIP", None)
        self.name = agent_dict.get("name", None)
        self.configSum = agent_dict.get("configSum", None)

    def get_end_of_life_date_from_database(self):
        # TODO: allow users to configure whether to use eol, support, or extendedSupport
        # TODO: this should be configurable per OS and should be stored in a config file
        with SQLiteDatabase(database_file_name=self.sqlite_filename) as database:
            select_statement = "SELECT eol FROM EOLData WHERE platform=? AND (cycle=? OR cycle=?)"
            sql_arguments = (self.OS.platform, self.OS.major_minor, self.OS.major)
            database.cursor.execute(select_statement, sql_arguments)
            result = database.cursor.fetchall()
            if not result:
                raise UnsupportedOSException(f"Platform: `{self.OS.platform}`, Major/Minor version: `{self.OS.major_minor}`")
            self.end_of_life_date = result[0][0]
