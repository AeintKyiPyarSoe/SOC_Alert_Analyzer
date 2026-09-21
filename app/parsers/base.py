from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseParser(ABC):
    """Abstract base class for all log parsers."""
    
    @abstractmethod
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse raw log text content and return a list of raw event dictionaries.
        Each dictionary will subsequently be normalized.
        """
        pass
