from rich import print
from rich.console import Console


class Logger:
    def __init__(self):
        self.console = Console()

    def info(self, message: str):
        print(f"[cyan][INFO][/cyan] {message}")

    def success(self, message: str):
        print(f"[green][SUCCESS][/green] {message}")

    def warning(self, message: str):
        print(f"[yellow][WARNING][/yellow] {message}")

    def error(self, message: str):
        print(f"[red][ERROR][/red] {message}")
