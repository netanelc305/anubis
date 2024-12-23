import logging
import re
from dataclasses import dataclass
from pathlib import Path

from plumbum import local

from anubis.collectors.base_collector import BaseCollector
from anubis.common import EnhancedDict

logger = logging.getLogger(__name__)
NM = local['nm']


@dataclass
class NmCollector(BaseCollector):
    """ A collector that extracts symbol information using nm. """

    modules: list[dict[str, str]]

    @classmethod
    def from_rule(cls, rule: list[dict[str, str]]) -> 'NmCollector':
        return cls(rule)

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        res = EnhancedDict()
        for module in self.modules:
            path, pattern = module['path'], module['pattern']
            logger.info(f'Collecting {path} with pattern {pattern}')
            data = NM(root_path / path)
            res[path] = re.findall(pattern, data)
        res.save_to_yaml(output_dir / 'nm.yaml')
