import logging
import posixpath
from dataclasses import dataclass
from pathlib import Path

from plumbum import local

from anubis.collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)
XCRUN = local['xcrun']


@dataclass
class SectionCollector(BaseCollector):
    """ A collector that extracts a given section. """

    modules: list[dict[str, str]]

    @classmethod
    def from_rule(cls, rule: list[dict[str, str]]) -> 'SectionCollector':
        return cls(rule)

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        for module in self.modules:
            path, segment, section = module['path'], module['segment'], module['section']
            logger.info(f'Collecting {path}:{segment}:{section}')
            XCRUN('segedit', root_path / path, '-extract', segment, section,
                  output_dir / f'{posixpath.basename(path)}_{segment}_{section}.bin')
