from rich import print
from rich.console import Console


class Logger:
    LEVELS = {"SILENT": 0, "ERROR": 1, "WARNING": 2, "INFO": 3, "DEBUG": 4}

    def __init__(self, level: str = "INFO"):
        self.console = Console()
        self.level = self.LEVELS.get(level.upper(), 3)

    def set_level(self, level: str):
        self.level = self.LEVELS.get(level.upper(), 3)

    def debug(self, message: str):
        if self.level >= self.LEVELS["DEBUG"]:
            print(f"[blue][DEBUG][/blue] {message}")

    def info(self, message: str):
        if self.level >= self.LEVELS["INFO"]:
            print(f"[cyan][INFO][/cyan] {message}")

    def success(self, message: str):
        if self.level >= self.LEVELS["INFO"]:
            print(f"[green][SUCCESS][/green] {message}")

    def warning(self, message: str):
        if self.level >= self.LEVELS["WARNING"]:
            print(f"[yellow][WARNING][/yellow] {message}")

    def error(self, message: str):
        if self.level >= self.LEVELS["ERROR"]:
            print(f"[red][ERROR][/red] {message}")
