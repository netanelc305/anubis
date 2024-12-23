import logging
import re
from dataclasses import dataclass
from pathlib import Path

from plumbum import local

from anubis.collectors.base_collector import BaseCollector
from anubis.common import EnhancedDict

logger = logging.getLogger(__name__)

STRINGS = local['strings']


@dataclass
class StringsCollector(BaseCollector):
    """ A collector that processes files using the `strings` command to extract patterns. """

    files: list[dict[str, str]]

    @classmethod
    def from_rule(cls, rule: list[dict[str, str]]):
        return cls(rule)

    async def collect(self, root_path: Path, output_dir: Path):
        res = EnhancedDict()
        for file in self.files:
            path, pattern = file['path'], file['pattern']
            logger.info(f'Collecting {path}...')
            data = STRINGS(str(root_path / path))
            res[path] = list(set(re.findall(pattern, data)))
        res.save_to_yaml(output_dir / 'strings.yaml')
