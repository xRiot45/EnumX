import os

from handlers import HANDLERS
from utils.logger import Logger

logger = Logger()


class Reporting:
    @staticmethod
    def save(results, filename, format_type="json"):
        os.makedirs("output", exist_ok=True)
        folder_map = {
            "json": "output/json",
            "csv": "output/csv",
            "txt": "output/txt",
            "xlsx": "output/xlsx",
            "html": "output/html",
            "md": "output/md",
        }
        folder = folder_map.get(format_type)
        os.makedirs(folder, exist_ok=True)
        
        base, _ = os.path.splitext(filename)
        filename = f"{base}.{format_type}"
        
        filepath = os.path.join(folder, filename)
        
        for module, data in results.items():
            handler_cls = HANDLERS.get(module)
            if handler_cls:
                handler_cls.save(data, filepath, format_type)
            else:
                logger.warning(f"No handler for module: {module}")
