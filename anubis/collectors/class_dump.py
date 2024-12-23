import logging
import re
from dataclasses import dataclass
from pathlib import Path

from anubis.collectors.base_collector import BaseCollector
from anubis.common import DSC_PATH, IPSW, EnhancedDict, get_dylibs_names_from_dsc

logger = logging.getLogger(__name__)


@dataclass
class ClassDumpCollector(BaseCollector):
    """ Collector for extracting class dump information. """

    rules: list[dict[str, str]]

    @classmethod
    def from_rule(cls, rule: list[dict[str, str]]) -> 'ClassDumpCollector':
        return cls(rule)

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        res = EnhancedDict()
        dylibs = get_dylibs_names_from_dsc(root_path)
        for rule in self.rules:
            path, pattern = rule['path'], rule['pattern']
            logger.info(f'Collecting {path}...')
            if f'{path}' in dylibs:
                data = IPSW('class-dump', str(root_path / DSC_PATH), path)
            else:
                data = IPSW('class-dump', str(root_path / path))
            res[path] = re.findall(pattern, data)

        res.save_to_yaml(output_dir / 'class-dump.yaml')
