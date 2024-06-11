from datetime import datetime
from OperatingSystem import OperatingSystem
from SQLiteDatabase import SQLiteDatabase


class UnsupportedOSException(Exception):
    pass

class UnsupportedEOLColumn(Exception):
    pass


class WazuhAgent:
    def __init__(self, agent_dict: dict, sqlite_filename: str, config_dict: dict) -> None:
        self.sqlite_filename = sqlite_filename
        self.config_dict = config_dict
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
        with SQLiteDatabase(database_file_name=self.sqlite_filename) as database:
            column_name = self.config_dict["EOL_column"]
            if column_name == "eol":
                select_statement = "SELECT eol FROM EOLData WHERE platform=? AND (cycle=? OR cycle=?)"
            elif column_name == "support":
                select_statement = "SELECT support FROM EOLData WHERE platform=? AND (cycle=? OR cycle=?)"
            elif column_name == "extendedSupport":
                select_statement = "SELECT extendedSupport FROM EOLData WHERE platform=? AND (cycle=? OR cycle=?)"
            elif column_name == "lts":
                select_statement = "SELECT lts FROM EOLData WHERE platform=? AND (cycle=? OR cycle=?)"
            else:
                raise UnsupportedEOLColumn(column_name)
            sql_arguments = (self.OS.platform, self.OS.major_minor, self.OS.major)
            database.cursor.execute(select_statement, sql_arguments)
            result = database.cursor.fetchall()
            if not result:
                raise UnsupportedOSException(f"Platform: `{self.OS.platform}`, Major/Minor version: `{self.OS.major_minor}`")
            end_of_life_date_string = result[0][0]
            self.end_of_life_date = datetime.strptime(end_of_life_date_string, "%Y-%m-%d").date()
            self.today = datetime.today().date()
            self.days_until_EOL = (self.end_of_life_date - self.today).days

    @property
    def time_until_EOL(self):
        if self.days_until_EOL < 0:
            EOL_message = f"The OS on this machine reached end of life {abs(self.days_until_EOL)} days ago!"
        elif self.days_until_EOL == 0:
            EOL_message = "The OS on this machine reaches end of life today!"
        elif self.days_until_EOL > 0:
            EOL_message = f"The OS on this machine reaches end of life in {self.days_until_EOL} days."
        return EOL_message
