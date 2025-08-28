from rich.console import Console
from rich.theme import Theme

global_console = Console(
    theme=Theme({"info": "cyan", "success": "green", "warning": "yellow", "error": "bold red"}),
    force_terminal=True,
    stderr=True,
)


class Logger:
    def __init__(self):
        self.console = global_console
        self.level = "DEBUG"

    def set_level(self, level: str):
        self.level = level.upper()

    def info(self, msg: str):
        if self.level != "SILENT":
            self.console.log(f"[info][INFO][/info] {msg}")

    def success(self, msg: str):
        if self.level != "SILENT":
            self.console.log(f"[success][SUCCESS][/success] {msg}")

    def warning(self, msg: str):
        if self.level != "SILENT":
            self.console.log(f"[warning][WARNING][/warning] {msg}")

    def error(self, msg: str):
        if self.level != "SILENT":
            self.console.log(f"[error][ERROR][/error] {msg}")


global_logger = Logger()
