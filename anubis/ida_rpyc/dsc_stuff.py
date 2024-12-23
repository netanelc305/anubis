import logging

import idaapi
import idc

logger = logging.getLogger(__name__)


def analyze() -> None:
    """ Run the IDA analysis and load Objective-C plugins. """
    logger.info('Analyzing...')
    idc.auto_mark_range(0, idc.BADADDR, idc.AU_FINAL)
    idc.auto_wait()

    for action in [1, 4, 5]:
        # 1. Analyze objc segments
        # 4. Analyze NSConcreteGlobalBlock objects
        # 5. Analyze NSConcreteStackBlock objects
        idc.load_and_run_plugin('objc', action)

    idc.auto_wait()
    logger.info('Analysis completed.')


def dscu_load_module(module: str) -> None:
    """ Load a single module into IDA. """
    node = idaapi.netnode()
    node.create('$ dscu')
    node.supset(2, module)
    idc.load_and_run_plugin('dscu', 1)
    idc.auto_wait()


def dscu_load_modules(modules: list[str]) -> None:
    """ Load multiple modules into IDA. """
    for module in modules:
        logger.info(f'Loading module: {module}')
        dscu_load_module(module)
    analyze()


def dscu_load_region(ea: int) -> None:
    """ Load a single memory region into IDA. """
    node = idaapi.netnode()
    node.create('$ dscu')
    node.altset(3, ea)
    idc.load_and_run_plugin('dscu', 2)
    idc.auto_wait()


def dscu_load_regions(regions: list[int]) -> None:
    """ Load multiple memory regions into IDA. """
    for region in regions:
        logger.debug(f'Loading region: {hex(region)}')
        dscu_load_region(region)
    analyze()
