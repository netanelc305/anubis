import asyncio
import json
import logging
import re
from collections import UserDict
from pathlib import Path
from typing import Any

import yaml
from plumbum import local

IPSW = local['/opt/homebrew/bin/ipsw']
DSC_PATH = Path('System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e')
EXTENSIONS_BLACKLIST = ('.i64', '.dyldlinkedit', '.symbols', '.BinExport', '.id0')
DYLD_SHARED_CACHE_PATTERN = re.compile(r'^dyld_shared_cache_arm64e(\..+)?$')
MAX_DEPTH = 5
RG_PATH = '/opt/homebrew/bin/rg'
YAML_UNDEFINED_TAG = 'tag:yaml.org,2002:str'

logger = logging.getLogger(__name__)


class AnubisYamlDumper(yaml.Dumper):
    """ Anubis YAML dumper that registers specific representers. """
    pass


class EnhancedDict(UserDict):
    """ A dictionary subclass that provides additional functionality such as inversion and YAML saving. """

    def invert(self) -> 'EnhancedDict':
        """ Invert the dictionary, swapping keys and values while maintaining structure. """
        inverted = {}
        for outer_key, value in self.data.items():
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    if inner_key not in inverted:
                        inverted[inner_key] = {outer_key: inner_value}
                    else:
                        inverted[inner_key][outer_key] = inner_value
            elif isinstance(value, list):
                for item in value:
                    inverted.setdefault(item, []).append(outer_key)
            else:
                inverted.setdefault(value, []).append(outer_key)
        return EnhancedDict(inverted)

    def save_to_yaml(self, output_file: Path) -> None:
        """ Save the dictionary to a YAML file. """
        with output_file.open('w', encoding='utf-8') as file:
            data_str_keys = {str(k): v for k, v in self.data.items()}
            yaml.dump(data_str_keys, file, Dumper=AnubisYamlDumper, sort_keys=True, indent=4)

    def __str__(self) -> str:
        """ String representation of the dictionary. """
        return '\n'.join(f'{k}: {v}' for k, v in self.data.items())


def anubis_dumper_representeter(dumper: yaml.Dumper, data: Any) -> yaml.Node:
    """ Anubis YAML representer for EnhancedDict and related data structures. """
    if isinstance(data, dict):
        return dumper.represent_dict(sorted(data.items()))
    elif isinstance(data, list):
        return dumper.represent_list(sorted(data, key=str))
    elif isinstance(data, tuple):
        return dumper.represent_scalar(YAML_UNDEFINED_TAG, ', '.join(map(str, data)))
    return dumper.represent_data(data)


AnubisYamlDumper.add_representer(EnhancedDict, anubis_dumper_representeter)
AnubisYamlDumper.add_representer(dict, anubis_dumper_representeter)
AnubisYamlDumper.add_representer(list, anubis_dumper_representeter)
AnubisYamlDumper.add_representer(tuple, anubis_dumper_representeter)


def get_dylibs_names_from_dsc(root_path: Path) -> list[str]:
    """ Retrieve a list of dylib names from the dyld_shared_cache. """
    dsc_related = IPSW('dsc', 'info', '-l', '--json', str(root_path / DSC_PATH))
    return [d['name'] for d in json.loads(dsc_related)['dylibs']]


async def run_ripgrep(root_path: Path, patterns: list[str],
                      excludes_extensions: list[str] = EXTENSIONS_BLACKLIST) -> EnhancedDict:
    """ Run ripgrep to find patterns in files within a directory. """
    cmd = [
        RG_PATH,
        '-a',  # Search binary files as if they were text
        '--no-heading',  # Remove filepath header for each result set
        '-o',  # Print only the matched (non-empty) parts of the matching line
        '-e',
        '|'.join(patterns),
        str(root_path)
    ]

    patterns_fmt = '\n\t'.join(patterns)
    logger.info(f'Running ripgrep on patterns:\n\t{patterns_fmt}')

    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if stderr:
        logger.error(f'Error: {stderr.decode("utf-8")}')

    res = EnhancedDict()
    for line in set(stdout.decode('utf-8').splitlines()):
        matched_file, pattern = line.split(':', 1)
        file_name = Path(matched_file).relative_to(root_path)

        if excludes_extensions and file_name.suffix in excludes_extensions:
            continue
        if DYLD_SHARED_CACHE_PATTERN.match(file_name.name):
            continue

        file_name = str(file_name)
        res.setdefault(pattern, []).append(file_name)

    return res
