import os

from utils.logger import Logger

logger = Logger()

DEFAULT_WORDLISTS = [
  "www", "mail", "ftp", "dev", "test", "api", "staging", "blog", "admin", "portal"
]

def load_wordlist(path: str=None):
    if path:
        if not os.path.isfile(path):
            logger.warning("Wordlist file not found, using default wordlists.")
            return DEFAULT_WORDLISTS
        
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as file:
                wordlists = [line.strip() for line in file if line.strip()]
                if wordlists:
                    logger.success(f"Loaded {len(wordlists)} wordlists from {path}.")
                    return wordlists
                else:
                    logger.warning("Wordlist file is empty, using default wordlists.")
                    return DEFAULT_WORDLISTS
        except Exception as e:
            logger.error(f"Error reading wordlist file: {e}. Using default wordlists.")
            return DEFAULT_WORDLISTS
    
    logger.info("No wordlist file provided, using default wordlists.")
    return DEFAULT_WORDLISTS
