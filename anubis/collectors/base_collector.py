import logging
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BaseCollector:
    """ Abstract base class for collectors. """

    @classmethod
    @abstractmethod
    def from_rule(cls, rule: dict) -> 'BaseCollector':
        """ Create a collector instance from a rule dictionary. """
        pass

    @abstractmethod
    def collect(self, root_path: Path, output_dir: Path) -> None:
        """ Collect data based on the given root path and output directory. """
        pass


@dataclass
class FilesCollector(BaseCollector):
    """ A Collector that handles file-based collection. """

    files: list[Path]

    @classmethod
    def from_rule(cls, rule: dict) -> 'FilesCollector':
        """ Create a FilesCollector instance from a rule dictionary. """
        return cls([Path(path) for path in rule['paths']])

    @abstractmethod
    def collect(self, root_path: Path, output_dir: Path) -> None:
        """ Collect files from the specified root path and save them in the output directory. """
        pass
