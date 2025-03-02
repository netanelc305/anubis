import asyncio
import logging
import traceback
from pathlib import Path
from typing import Optional

import click
import coloredlogs
import yaml

from anubis.collectors.binexport import BinExportCollector
from anubis.collectors.class_dump import ClassDumpCollector
from anubis.collectors.nm import NmCollector
from anubis.collectors.objc_protocol_selectors import ObjcProtocolSelectors
from anubis.collectors.plist import PlistCollector
from anubis.collectors.regs_tracker import RegsTrackerCollector
from anubis.collectors.rg import RgCollector
from anubis.collectors.section import SectionCollector
from anubis.collectors.strings import StringsCollector

coloredlogs.install(level=logging.DEBUG)
logging.getLogger('urllib3.connectionpool').disabled = True
logging.getLogger('root').disabled = True
logging.getLogger('plumbum.local').disabled = True
logging.getLogger('asyncio').disabled = True

logger = logging.getLogger('anubis')

TASK_TIMEOUT = 20
COLLECTORS = {'rg': RgCollector, 'binexport': BinExportCollector, 'plist': PlistCollector,
              'class-dump': ClassDumpCollector, 'strings': StringsCollector, 'regs-tracker': RegsTrackerCollector,
              'nm': NmCollector, 'section': SectionCollector, 'objc-protocol-selectors': ObjcProtocolSelectors}


async def collect_task(input_path: Path, output_path: Path, rules: dict, whitelist: Optional[set] = None,
                       blacklist: Optional[set] = None):
    tasks = []
    skip_list = []
    for name, rule in rules.items():
        if (blacklist and name in blacklist) or (whitelist and name not in whitelist):
            skip_list.append(name)
            continue
        try:
            collector = COLLECTORS[name].from_rule(rule)
        except KeyError:
            logger.error(f'Unknown collector: {name}')
            continue
        tasks.append(asyncio.create_task(collector.collect(input_path, output_path), name=name))

    if len(skip_list) > 0:
        logger.info(f'Skipping Collectors: {", ".join(sorted(skip_list))}')

    while tasks:
        done, tasks = await asyncio.wait(tasks, timeout=TASK_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception():
                logger.error(
                    f'Collector {task.get_name()} failed with exception: {task.exception()}\n{traceback.format_exc()}')
            else:
                logger.info(f'Collector completed successfully: {task.get_name()}')
        running = ', '.join(sorted([task.get_name() for task in tasks if not task.done()]))
        logger.info(f'Still Running: {running}')

    logger.info('All collectors completed.')


@click.group()
def cli():
    pass


@cli.command()
@click.argument('input_path', type=click.Path(exists=True, dir_okay=True, file_okay=False))
@click.argument('output_path', type=click.Path(exists=False, dir_okay=True, file_okay=False))
@click.argument('rules', type=click.Path(exists=True))
@click.option('collectors', '-c', '--collector', multiple=True)
@click.option('blacklist', '-b', '--blacklist', multiple=True)
def collect(input_path: str, output_path: str, rules: str, collectors: tuple[str], blacklist: tuple[str]):
    input_path, output_path = Path(input_path), Path(output_path)
    output_path.mkdir(exist_ok=True, parents=True)
    with open(rules, 'r') as f:
        data = yaml.safe_load(f)
    wlist = set(collectors) if collectors else None
    blist = set(blacklist) if blacklist else None
    asyncio.run(collect_task(input_path, output_path, data, wlist, blist))


if __name__ == '__main__':
    cli()
