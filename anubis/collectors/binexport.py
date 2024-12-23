import asyncio
import logging
from pathlib import Path

from idascript import IDA

from anubis.collectors.base_collector import FilesCollector

logger = logging.getLogger(__name__)


class BinExportCollector(FilesCollector):
    """ Collector for exporting binary analysis results using IDA. """

    async def collect(self, root_path: Path, output_dir: Path) -> None:
        output_dir = output_dir / 'binexport'
        output_dir.mkdir(exist_ok=True)

        for file in self.files:
            logger.info(f'Collecting {file}...')
            output_file = output_dir / Path(file.name).with_suffix('.BinExport')

            ida = IDA(
                root_path / file,
                script_file=None,
                script_params=[
                    'BinExportAutoAction:BinExportBinary',
                    f'BinExportModule:{output_file}',
                ],
            )
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, ida.start)
            await loop.run_in_executor(None, ida.wait)

            if output_file.exists():
                logger.info(f'Done {output_file}...')
