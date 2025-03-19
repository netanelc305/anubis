import dataclasses
import logging
import plistlib
import tempfile
from pathlib import Path

import yaml
from plumbum import local

logger = logging.getLogger(__name__)

YQ = local['/opt/homebrew/bin/yq']


@dataclasses.dataclass()
class PlistCollector:
    """ Collector for processing plist files and converting them to YAML format. """

    rules: list[dict[str, str]]

    @classmethod
    def from_rule(cls, rule: list[dict[str, str]]) -> 'PlistCollector':
        return cls(rule)

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        output_dir = output_dir / 'plist'
        output_dir.mkdir(exist_ok=True)

        for rule in self.rules:
            file = rule['file']
            file_path = root_path / file
            if not file_path.exists():
                logger.warning(f'File {file_path} does not exist')
                continue
            logger.info(f'Processing plist file: {file}')

            with file_path.open('rb') as plist_file:
                data = plistlib.load(plist_file)

            yq_query = rule.get('yq_query')
            if yq_query:
                logger.info(f'Running yq query: {yq_query}')
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as fp:
                    yaml.dump(data, fp, sort_keys=True, indent=4)
                    data = YQ(yq_query, fp.name).splitlines()

            output_path = output_dir / f'{file_path.name}.yaml'
            with output_path.open('w') as output_file:
                yaml.dump(data, output_file, sort_keys=True, indent=4)

            logger.info(f'Converted plist to YAML: {output_path}')
