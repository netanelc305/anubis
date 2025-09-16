import asyncio
import logging
import traceback
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from tqdm import tqdm

from anubis.collectors.base_collector import BaseCollector
from anubis.common import DSC_PATH, EnhancedDict, get_dylibs_names_from_dsc, run_ripgrep
from anubis.ida_rpyc.ida_client import DscIdb, MachoIdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

IDA_PATH = '/Applications/IDA Professional 9.2.app/Contents/MacOS/ida'


@dataclass(frozen=True)
class SearchRule:
    """ A search rule defining a function and associated registers. """
    function: str
    registers: tuple[str]


@dataclass
class RegsTrackerTaskMacho:
    """ A task for tracking registers in Mach-O files using IDA. """
    root_path: str
    file_path: str
    search_rules: set[SearchRule]

    @contextmanager
    def idb_context(self, ida_path: str):
        """ Context manager for regular tasks using MachoIdb. """
        with MachoIdb(ida_path, f'{self.root_path}/{self.file_path}') as idb:
            yield idb


@dataclass
class RegsTrackerTaskDsc(RegsTrackerTaskMacho):
    """ A task for tracking registers in a DSC file using IDA. """
    dsc_path: str

    @contextmanager
    def idb_context(self, ida_path: str):
        """ Context manager for DSC tasks using DscIdb. """
        with DscIdb(ida_path, self.file_path, self.dsc_path) as idb:
            yield idb


def reg_tracker_worker(task: Union[RegsTrackerTaskDsc, RegsTrackerTaskDsc]):
    """ Worker function for processing a register tracking task. """
    try:
        results = {}
        with task.idb_context(IDA_PATH) as idb:
            for rule in task.search_rules:
                results[rule.function] = idb.track_function_registers(rule.function, rule.registers)
        return task.file_path, results
    except Exception as e:
        logger.error(f'Error for task {task} traceback: {e}\n{traceback.format_exc()}')
        raise


@dataclass
class RegsTrackerCollector(BaseCollector):
    """ Collector for tracking register values of a given function. """
    ida_path: str
    search_rules: dict[str, tuple[str]]

    @classmethod
    def from_rule(cls, rule) -> 'RegsTrackerCollector':
        """ Create an IDBCollector instance from a rule definition. """
        return cls(IDA_PATH, {p['func_pattern']: tuple(p['registers']) for p in rule})

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        matches = await self._find_matches(root_path)
        tasks = await self._create_tasks(root_path, matches.invert())
        results = await self._process_tasks(tasks)

        inverted_results = EnhancedDict(results).invert()
        output_dir = output_dir / 'regs_tracker'
        output_dir.mkdir(parents=True, exist_ok=True)
        for func, results in inverted_results.items():
            output_file = output_dir / f'{func.replace(":", "_")}.yaml'
            EnhancedDict(results).save_to_yaml(output_file)

    async def _create_tasks(self, root_path: Path, matches: EnhancedDict):
        """ Create tasks for register tracking based on matched patterns. """
        tasks = []
        dylibs = get_dylibs_names_from_dsc(root_path)
        for k, v in matches.items():
            if f'/{k}' in dylibs:
                task = RegsTrackerTaskDsc(str(root_path), f'/{k}', set([(SearchRule(p, self.search_rules[p])) for p in v]),
                                          dsc_path=str(root_path / DSC_PATH))
            else:
                task = RegsTrackerTaskMacho(str(root_path), k, set([(SearchRule(p, self.search_rules[p])) for p in v]))
            tasks.append(task)

        return tasks

    @staticmethod
    async def _process_tasks(tasks: list[Union[RegsTrackerTaskMacho, RegsTrackerTaskDsc]]):
        """ Process tracking tasks using a process pool. """
        loop = asyncio.get_running_loop()
        results = {}
        with ProcessPoolExecutor() as executor:
            futures = [loop.run_in_executor(executor, reg_tracker_worker, task) for task in tasks]
            for future in tqdm(asyncio.as_completed(futures), total=len(tasks), desc='Processing regs-tracker tasks'):
                file_path, result = await future
                results[file_path] = result
        return results

    async def _find_matches(self, root_path: Path) -> EnhancedDict:
        """ Find matches by running ripgrep with the given search rules. """
        return await run_ripgrep(root_path, list(self.search_rules.keys()))
