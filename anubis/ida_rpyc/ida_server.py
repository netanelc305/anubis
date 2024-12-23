import importlib
import logging

import dsc_stuff
import ida_auto
import ida_loader
import ida_pro
import idc
import rpyc

from anubis.common import MAX_DEPTH
from anubis.ida_rpyc.regs_tracker.ida_reg_tracker import track_function_registers

logger = logging.getLogger(__name__)


class IDATrackService(rpyc.Service):
    """Service for tracking function registers using IDA Pro."""

    def __init__(self) -> None:
        """Initialize the service and wait for IDA to be ready."""
        super().__init__()
        ida_auto.auto_wait()

    def on_connect(self, conn):
        ida_loader.set_database_flag(ida_loader.DBFL_KILL | ida_loader.DBFL_TEMP)

    def on_disconnect(self, conn) -> None:
        """Handle client disconnection by exiting IDA."""
        ida_pro.qexit(0)

    def exposed_import_module(self, mod: str):
        """Dynamically import a module by name."""
        return importlib.import_module(mod)

    def exposed_track_function_registers(self, name: str, registers: list[str], max_depth: int = MAX_DEPTH):
        """Track specified registers in a given function with a maximum search depth."""
        return track_function_registers(name, registers, max_depth)

    def exposed_load_modules(self, modules: list[str]) -> None:
        """Load specified modules using dsc_stuff."""
        dsc_stuff.dscu_load_modules(modules)

    def exposed_load_regions(self, regions: list[int]) -> None:
        """Load specified memory regions using dsc_stuff."""
        dsc_stuff.dscu_load_regions(regions)


if __name__ == '__main__':
    server = rpyc.OneShotServer(
        service=IDATrackService,
        port=idc.ARGV[1],
        protocol_config={
            'allow_public_attrs': True,
            'import_custom_exceptions': True,
        }
    )
    rpyc.lib.setup_logger()
    server.start()
