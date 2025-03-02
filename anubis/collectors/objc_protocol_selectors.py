import logging
import re
from dataclasses import dataclass
from pathlib import Path

from anubis.collectors.base_collector import BaseCollector
from anubis.common import DSC_PATH, IPSW, EnhancedDict, get_dylibs_names_from_dsc

logger = logging.getLogger(__name__)


@dataclass
class ObjcProtocolSelectors(BaseCollector):
    """ Collector for extracting selectors for given objc protocol. """

    rules: list[dict[str, str]]

    @classmethod
    def from_rule(cls, rule: list[dict[str, str]]) -> 'ObjcProtocolSelectors':
        return cls(rule)

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        """
        Use `class-dump` to generate a header file contents from given executable.
        Then, look for all protocol selectors by searching for all the selectors between `<protocol>`
        to `@end`.

        :param root_path: Extracted IPSW root path.
        :param output_dir: Output directory of where write `objc-protocol-selectors.yaml`.
        :return: None
        """
        res = EnhancedDict()
        dylibs = get_dylibs_names_from_dsc(root_path)
        for rule in self.rules:
            path, protocol = rule['path'], rule['protocol']
            logger.info(f'Collecting {path}...')
            if f'{path}' in dylibs:
                data = IPSW('class-dump', str(root_path / DSC_PATH), path)
            else:
                data = IPSW('class-dump', str(root_path / path))

            protocol_chunk = data.split(f'<{protocol}>')
            if len(protocol_chunk) < 2:
                # No protocol matches were found
                return

            # Iterate each protocol header
            for chunk in protocol_chunk[1:]:
                # Get protocol header body
                protocol_body = chunk.split('@end', 1)[0]

                # Match protocol's selectors
                selectors = re.findall(r'-\[.+?]', protocol_body)

                # Append all matched selectors
                if path not in res:
                    res[path] = []
                res[path] += selectors

            # Make sure the result is always sorted the same way for easier diff-ing
            res[path].sort()

        res.save_to_yaml(output_dir / 'objc-protocol-selectors.yaml')
