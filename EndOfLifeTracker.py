import glob
import json
import os
import yaml
from SQLiteDatabase import SQLiteDatabase
from WazuhAgent import WazuhAgent, UnsupportedOSException


class FailedToParseConfigFileException(Exception):
    pass


class SQLiteDatabaseAlreadyExistsException(Exception):
    pass


class UnsupportedWazuhPlatformException(Exception):
    pass


class EndOfLifeTracker:
    def __init__(self) -> None:
        self.read_config_from_file()
        self.sqlite_filename = "end_of_life.db"
        if not os.path.exists(self.sqlite_filename):
            self.initialize_sqlite_database()
            self.read_raw_data_folder()

        self.wazuh_agents: list[WazuhAgent] = []
        self.load_agent_data()
        self.supported_os = {}

    def initialize_sqlite_database(self):
        """
        Initializes the local SQLite database used to store end of life information
        """
        print(f"Initializing the SQLite database `{self.sqlite_filename}`...")
        if os.path.exists(self.sqlite_filename):
            raise SQLiteDatabaseAlreadyExistsException(f"Failed to initialize the SQLite database because the filename `{self.sqlite_filename}` already exists!")

        with SQLiteDatabase(database_file_name=self.sqlite_filename) as database:
            create_EOLData_table = "CREATE TABLE EOLData(id INTEGER PRIMARY KEY, platform TEXT, cycle TEXT, codename TEXT, latest TEXT, releaseDate TEXT, latestReleaseDate TEXT, eol TEXT, support TEXT, extendedSupport TEXT, lts BOOL)"
            database.cursor.execute(create_EOLData_table)
            database.connection.commit()
        print(f"Successfully initialized the SQLite database `{self.sqlite_filename}`.")

    def add_release_to_database(self, platform: str, release_dict: dict):
        with SQLiteDatabase(database_file_name=self.sqlite_filename) as database:
            insert_statement = "INSERT INTO EOLData(platform, cycle, codename, latest, releaseDate, latestReleaseDate, eol, support, extendedSupport, lts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            sql_arguments = (
                platform,
                release_dict.get("cycle"),
                release_dict.get("codename"),
                release_dict.get("latest"),
                release_dict.get("releaseDate"),
                release_dict.get("latestReleaseDate"),
                release_dict.get("eol"),
                release_dict.get("support"),
                release_dict.get("extendedSupport"),
                release_dict.get("lts"),
            )  # a tuple is expected so we need the trailing comma
            database.cursor.execute(insert_statement, sql_arguments)
            database.connection.commit()
            return database.cursor.lastrowid

    def read_config_from_file(self):
        try:
            config_file_name = "./config.yaml"
            with open(config_file_name, "r") as file_in:
                yaml_dict = yaml.safe_load(file_in)
                self.operating_systems = yaml_dict["operating_systems"]
                self.days_until_EOL_warning = yaml_dict["days_until_EOL_warning"]
        except Exception as err:
            raise FailedToParseConfigFileException(err)

    def get_config_matching_operating_system(self, wazuh_platform: str):
        for operating_system in self.operating_systems:
            if operating_system["wazuh_platform"] == wazuh_platform:
                return operating_system
        raise UnsupportedWazuhPlatformException(wazuh_platform)

    def read_json_from_file(self, filename):
        with open(filename, "r") as file_in:
            return json.load(file_in)

    def load_agent_data(self):
        agent_data = self.read_json_from_file(filename="agent_data.json")

        for agent in agent_data["data"]["affected_items"]:
            try:
                if agent["id"] == "000": # skip the wazuh-manager
                    continue
                config_dict = self.get_config_matching_operating_system(wazuh_platform=agent["os"]["platform"])
                wazuh_agent = WazuhAgent(agent_dict=agent, sqlite_filename=self.sqlite_filename, config_dict=config_dict)
                self.wazuh_agents.append(wazuh_agent)
            except UnsupportedWazuhPlatformException as err:
                print(f"ERROR: Unsupported Wazuh platform: {err}\n")
            except UnsupportedOSException as err:
                print(f"ERROR: Unsupported OS: {err}\n")

    def read_raw_data_folder(self):
        supported_os = {}
        raw_data_files = [f for f in glob.glob("./raw_data/*.json")]
        for file in raw_data_files:
            file = os.path.abspath(file)
            filename = os.path.splitext(os.path.basename(file))[0]
            supported_os_data = self.read_json_from_file(filename=file)
            for release_dict in supported_os_data:
                self.add_release_to_database(platform=filename, release_dict=release_dict)
            supported_os[filename] = supported_os_data
        self.supported_os = supported_os

    def check_all_agents(self):
        for agent in self.wazuh_agents:
            if agent.days_until_EOL < self.days_until_EOL_warning:
                print(f"{agent.name},{agent.OS.name},{agent.OS.version},{agent.time_until_EOL}")
