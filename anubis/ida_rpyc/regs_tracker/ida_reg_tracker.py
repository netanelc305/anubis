import logging
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional

import ida_xref
import idautils
import idc

from anubis.ida_rpyc.regs_tracker.disassembler import DisplacementOperand, ImmediateOperand, Instruction, Register, \
    RegOperand
from anubis.ida_rpyc.regs_tracker.exceptions import UnmappedMemoryError

logger = logging.getLogger(__name__)

OBJC_RETAIN_PATTERN = re.compile(r'_objc_retain_(x\d+)')
FUNC_NAME_EXCLUDE = re.compile(r'\.cold\.\d+$')
SEGMENT_BLACKLIST = ['__auth_stubs']

REGISTER_WIDTH = 8
MAX_DEPTH = 10


class TrackerStatus(Enum):
    TRACKING = auto(),
    VALUE_FOUND = auto(),
    MAX_DEPTH = auto(),
    NO_XREFS = auto(),
    DATA_XREFS = auto(),
    NOT_SUPPORTED = auto(),


def handle_objc_retain(func_name: str) -> Register:
    """ Extracts source register from the given Objective-C retain function name. """
    reg = OBJC_RETAIN_PATTERN.match(func_name)
    if reg:
        return Register.from_str(reg.group(1))
    raise ValueError(f'Invalid function name: {func_name}')


BL_HANDLERS_REGEX: dict[re.Pattern, Callable[[str], Register]] = {
    re.compile(r'^_objc_msgSend\$stringWithFormat:$'): lambda func_name: Register.from_str('x2'),
    re.compile(r'^_objc_retain_'): handle_objc_retain,
}


def get_bl_handler(op_name: str) -> Optional[Callable[[str], Register]]:
    """ Retrieves the appropriate handler for a given branch instruction name. """
    for pattern, handler in BL_HANDLERS_REGEX.items():
        if pattern.match(op_name):
            return handler
    return None


@dataclass
class LogEntry:
    instruction: Instruction
    register: Register
    status: TrackerStatus
    comment: str = ''

    def __str__(self) -> str:
        operands_str = ', '.join(map(str, self.instruction.operands))
        address = f'{hex(self.instruction.ea):<12}'
        mnemonic = f'{self.instruction.mnemonic:<10}'
        operands = f'{operands_str:<60}'
        register = f'{str(self.register):<3}'
        # Use the enum's name for a concise status representation.
        status = f'{self.status.name:<15}'
        comment = self.comment or ''
        return f'{address}: {mnemonic} {operands} | {register} | {status} | {comment}'


class RegisterTracker:
    def __init__(self, target_register: Register, instruction: Instruction) -> None:
        self.target_register = target_register
        self.current_instruction = instruction
        self._current_register = self.target_register
        self._status = TrackerStatus.TRACKING
        self._value = None
        self.trace_log: list[LogEntry] = []

    def __repr__(self) -> str:
        """Custom representation of the register tracker."""
        return (f'RegisterTracker(target_register={self.target_register}, current_register={self.current_register},'
                f'status={self.status}, value={self.value})')

    def clone(self) -> 'RegisterTracker':
        """Creates a copy of the current register tracker."""
        cloned = RegisterTracker(self.target_register, self.current_instruction)
        cloned._current_register = self._current_register
        cloned._value = self._value
        cloned._status = self.status
        cloned.trace_log = self.trace_log[:]
        return cloned

    def record(self, comment: str) -> None:
        """Records an event in the tracker log."""
        self.trace_log.append(LogEntry(self.current_instruction, self._current_register, self.status, comment))

    @property
    def current_register(self) -> Register:
        return self._current_register

    @current_register.setter
    def current_register(self, value: Register) -> None:
        self.record(f'Changing register {self.current_register} -> {value}')
        self._current_register = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value) -> None:
        self._value = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value) -> None:
        self._status = value
        self.record(f'Status changed: {value}')

    @property
    def bt(self) -> str:
        """Provides a backtrace of the register tracking."""
        trace_lines = []
        for entry in reversed(self.trace_log):
            trace_lines.append(f'    {str(entry)}')
        return '\n'.join(trace_lines)

    def handle_current_instruction(self):
        instruction = self.current_instruction
        current_register = self.current_register
        # Handle 'BL' instructions, which often correspond to function calls.
        # Check if the mnemonic is 'BL' and if the current register is x0, which is commonly used for function arguments.
        if instruction.mnemonic == 'BL' and current_register == Register.from_str('x0') \
                and self.target_register != current_register:
            op1 = instruction.operands[0]

            # Ensure the operand is mapped to valid memory.
            if not op1.is_mapped:
                raise UnmappedMemoryError(op1.addr)

            # Attempt to find a handler for the called function.
            handler = get_bl_handler(op1.name)
            if handler is None:
                self.record('Unknown after call')
            else:
                self.current_register = handler(op1.name)

        # Check if the instruction writes to the register we are tracking.
        elif len(instruction.operands) > 1 and instruction.operands[0].reg == current_register:
            op2 = instruction.operands[1]

            # Handle MOV instructions.
            if instruction.mnemonic == 'MOV':
                if isinstance(op2, ImmediateOperand):
                    self.status = TrackerStatus.VALUE_FOUND
                    self.current_instruction = instruction
                # If the source is another register, update register to track
                elif isinstance(op2, RegOperand):
                    self.current_register = op2.reg

            # Handle ADRP/ADRL instructions.
            elif instruction.mnemonic in ['ADR', 'ADRP', 'ADRL']:
                # If the source is an immediate value,resolve and return.
                if isinstance(op2, ImmediateOperand):
                    self.status = TrackerStatus.VALUE_FOUND
                    self.current_instruction = instruction

            # Handle LDR instructions.
            elif instruction.mnemonic == 'LDR' and isinstance(op2, DisplacementOperand):
                # If the operand is a displacement (e.g., [base + offset]), track the base register.
                if op2.offset != 0:
                    self.status = TrackerStatus.NOT_SUPPORTED
                    self.value = hex(instruction.ea)
                else:
                    self.current_register = op2.base
            else:
                self.status = TrackerStatus.NOT_SUPPORTED
                self.value = hex(instruction.ea)

            if self.status == TrackerStatus.VALUE_FOUND:
                self.value = op2.resolve_data_value()

    @staticmethod
    def track_register_at(register: Register, start_address: int, max_depth: int = MAX_DEPTH) -> list['RegisterTracker']:
        """ Initiates tracking of a register starting from a given address. """
        instruction = Instruction.from_ea(start_address)
        tracker = RegisterTracker(register, instruction)
        tracker.record(f'Start Tracking {register} at {start_address}')
        return tracker._track_register_at(max_depth)

    def _track_register_at(self, max_depth: int = MAX_DEPTH) -> list['RegisterTracker']:
        """ Recursively tracks the register. """
        tracker = self
        result: list[RegisterTracker] = []

        # Base case: if the recursion depth has reached zero, stop tracking.
        current_instruction_ea = tracker.current_instruction.ea
        if max_depth == 0:
            tracker.status = TrackerStatus.MAX_DEPTH
            tracker.value = hex(current_instruction_ea)
            return [tracker]

        # Handle current instruction
        tracker.handle_current_instruction()
        if tracker.status != TrackerStatus.TRACKING:
            return [tracker]

        # At this point, the instruction didn't resolve the register value directly.
        # So, follow the xrefs (cross-references) to see where the value might come from.

        # Get all xrefs pointing to the current instruction's address.
        xrefs = list(idautils.XrefsTo(current_instruction_ea))
        if not xrefs:
            # If no cross-references are found, mark the value as unresolved.
            tracker.status = TrackerStatus.NO_XREFS
            tracker.value = hex(current_instruction_ea)
            return [tracker]

        # If there are cross-references, recursively trace through each one.
        for xref in xrefs:
            # Clone the trace entry for each xref to track distinct execution paths.
            new_tracker = tracker.clone()

            if not xref.iscode:
                # If the xref is not from code, it's likely a data reference.
                new_tracker.status = TrackerStatus.DATA_XREFS
                new_tracker.value = hex(xref.frm)
                result.append(new_tracker)
                continue

            new_tracker.current_instruction = Instruction.from_ea(xref.frm)

            if xref.type != ida_xref.fl_F:
                # If it's not a standard flow xref (BL), log the tracking action and decrease depth.
                new_tracker.record(f'Tracking x-refs to {hex(current_instruction_ea)}')
                result += new_tracker._track_register_at(max_depth - 1)
            else:
                # If it is a flow xref, continue tracking with the same depth.
                result += new_tracker._track_register_at(max_depth)

        return result


def get_function_addresses_by_name(name: str) -> list[tuple[int, str]]:
    """ Retrieves addresses of functions that match the given name. """
    matches = []
    for ea in idautils.Functions():
        func_name = idc.get_func_name(ea)
        if name in func_name:
            seg = idc.get_segm_name(ea)
            logger.info(seg)
            parts = seg.split(':')
            if len(parts) > 1 and parts[1] in SEGMENT_BLACKLIST:
                logger.info(f'Function {func_name} is blacklisted: {seg}')
                continue
            if FUNC_NAME_EXCLUDE.search(func_name):
                logger.info(f'Function {func_name} is blacklisted')
                continue
            matches.append((ea, func_name))

    return matches


def track_function_registers(name: str, registers: list[str], max_depth: int = MAX_DEPTH) -> dict[str, list[RegisterTracker]]:
    """ Tracks the specified registers within functions that match the given name. """
    func = get_function_addresses_by_name(name)
    results: dict[str, list[RegisterTracker]] = {}
    for ea, func_name in func:
        print(f'Function: {func_name} @ 0x{ea:X}')
        for r in registers:
            results[r] = RegisterTracker.track_register_at(Register.from_str(r), ea, max_depth)
    return results
