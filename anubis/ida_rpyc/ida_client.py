import logging
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import rpyc

from anubis.common import MAX_DEPTH
from anubis.ida_rpyc.regs_tracker.exceptions import UnmappedMemoryError

SERVER_SCRIPT = Path(__file__).parent / 'ida_server.py'

logger = logging.getLogger(__name__)
rpyc.core.vinegar._generic_exceptions_cache[
    'anubis.ida_rpyc.regs_tracker.exceptions.UnmappedMemoryError'
] = UnmappedMemoryError


class MachoIdb:
    """ Wrapper for interacting with IDA to analyze Mach-O binaries. """

    def __init__(self, ida_path: str, binary_path: str, ftype: str = 'Mach-O file', env: Optional[dict] = None) -> None:
        self.ida_path = ida_path
        self.binary_path = binary_path
        self.ftype = ftype
        self.env = {} if env is None else env
        self._conn = None

    def start(self) -> None:
        """ Launch IDA and establish a rpyc connection. """
        with socket.socket() as s:
            s.bind(('', 0))
            port = s.getsockname()[1]

        tempidb = tempfile.NamedTemporaryFile()
        command = f'"{self.ida_path}" -A -T"{self.ftype}" -o"{tempidb.name}" -S"{SERVER_SCRIPT} {port}" "{self.binary_path}"'
        self.env.update(os.environ.copy())

        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)

        while self._conn is None:
            if p.poll() is not None:
                raise Exception(
                    f'IDA failed to start: return code {p.poll()}\n'
                    f'Command: {command}\n'
                    f'=============== STDOUT ===============\n{p.stdout.read().decode()}'
                    f'=============== STDERR ===============\n{p.stderr.read().decode()}'
                )
            try:
                self._conn = rpyc.connect('localhost', port, config={'sync_request_timeout': 60 * 60 * 24})
            except ConnectionError:
                time.sleep(1)

    def stop(self) -> None:
        """ Close the rpyc connection. """
        self._conn.close()

    def track_function_registers(self, name: str, registers: tuple, max_depth: int = MAX_DEPTH) -> dict:
        """ Track function register values and return them as a Python object. """
        raw_results = self._conn.root.track_function_registers(name, registers, max_depth)
        results = {register: [(x.status.name, x.value) for x in value] for register, value in raw_results.items()}
        return results

    def __enter__(self) -> 'MachoIdb':
        """ Start the connection when entering a context. """
        self.start()
        return self

    def __exit__(self, exc_type: Optional[type], exc_value: Optional[Exception], traceback: Optional[Any]) -> None:
        """ Stop the connection when exiting a context. """
        self.stop()


class DscIdb(MachoIdb):
    """ Wrapper for analyzing Apple DYLD cache modules in IDA. """

    def __init__(self, ida_path: str, module: str, dsc_path: str) -> None:
        super().__init__(ida_path, dsc_path, 'Apple DYLD cache for arm64e (select module(s))',
                         {'IDA_DYLD_CACHE_MODULE': module})

    def track_function_registers(self, name: str, registers: tuple, max_depth: int = MAX_DEPTH) -> dict:
        """ Track function registers, handling unmapped memory errors by loading required regions. """
        ret = None
        loaded_regions = set()

        while ret is None:
            try:
                ret = super().track_function_registers(name, registers, max_depth)
            except UnmappedMemoryError as e:
                unmapped_address = e.address
                logger.warning(f'Got UnmappedMemoryError at: {hex(unmapped_address)}, trying to load region')

                if unmapped_address in loaded_regions:
                    raise e

                self._conn.root.load_regions([unmapped_address])
                loaded_regions.add(unmapped_address)
                logger.info(f'Region loaded {hex(unmapped_address)}, retrying...')

        return ret
