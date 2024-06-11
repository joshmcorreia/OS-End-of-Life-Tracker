class OperatingSystem:
    def __init__(self, os_dict: dict) -> None:
        self.parse_os_dict(os_dict=os_dict)

    def parse_os_dict(self, os_dict: dict):
        self.arch = os_dict.get("arch", None)
        self.codename = os_dict.get("codename", None)
        self.major = os_dict.get("major", None)
        self.minor = os_dict.get("minor", None)
        self.name = os_dict.get("name", None)
        self.platform = os_dict.get("platform", None)
        self.uname = os_dict.get("uname", None)
        self.version = os_dict.get("version", None)

    @property
    def major_minor(self):
        if not self.minor:
            return self.major
        return f"{self.major}.{self.minor}"
