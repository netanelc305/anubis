import logging
from dataclasses import dataclass
from pathlib import Path

from anubis.collectors.base_collector import BaseCollector
from anubis.common import EnhancedDict, run_ripgrep

logger = logging.getLogger(__name__)


@dataclass
class RgCollector(BaseCollector):
    """ Collector that searches for specific patterns within a given directory using ripgrep. """

    patterns: list[str]

    @classmethod
    def from_rule(cls, rule: dict) -> 'RgCollector':
        return cls(rule['patterns'])

    async def collect(self, root_path: Path, output_dir: Path):
        res = await run_ripgrep(root_path, self.patterns)
        EnhancedDict(res).save_to_yaml(output_dir / 'rg.yaml')
