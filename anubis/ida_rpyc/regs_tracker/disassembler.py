import logging
from dataclasses import dataclass, field
from typing import List, Optional, Union

import ida_bytes
import ida_idp
import ida_ua
import idc

logger = logging.getLogger(__name__)

REGISTER_WIDTH = 8


def extract_objc_string(nsstring_addr: int) -> Optional[str]:
    """Extracts an Objective-C string from memory if present."""
    c_string_addr = ida_bytes.get_64bit(nsstring_addr + 0x10)
    if c_string_addr:
        string = idc.get_strlit_contents(c_string_addr)
        if string:
            return string.decode('utf-8')
    return None


def extract_c_cstring(c_string_address: int) -> Optional[str]:
    """Extracts a C string from memory if present."""
    string = idc.get_strlit_contents(c_string_address)
    if string:
        return string.decode('utf-8')
    return None


@dataclass
class Register:
    """Represents a CPU register."""
    num: int

    @staticmethod
    def from_str(name: str) -> 'Register':
        """Creates a Register instance from a string name."""
        return Register(ida_idp.str2reg(name))

    def __str__(self) -> str:
        """Returns the register name as a string."""
        return ida_idp.get_reg_name(self.num, REGISTER_WIDTH)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Register) and self.num == other.num

    def __gt__(self, other: 'Register') -> bool:
        return self.num > other.num

    def __lt__(self, other: 'Register') -> bool:
        return self.num < other.num

    def __repr__(self) -> str:
        return f'Register(reg={str(self)})'


@dataclass
class Operand:
    """Base class for instruction operands."""
    pass


@dataclass
class RegOperand(Operand):
    """Represents a register operand."""
    reg: Register

    def __repr__(self) -> str:
        return f'RegOperand(reg={self.reg})'


@dataclass
class UnknownOperand(Operand):
    """Represents an unknown operand type."""
    op_type: int

    def __repr__(self) -> str:
        return f'UnknownOperand(type={self.op_type})'


@dataclass
class MemoryOperand(Operand):
    """Represents a memory address operand."""
    addr: int

    @property
    def name(self) -> str:
        """Returns the name of the memory location."""
        return idc.get_name(self.addr)

    @property
    def is_mapped(self) -> bool:
        """Checks if the memory address is mapped."""
        return idc.is_mapped(self.addr)

    def __repr__(self) -> str:
        return f'MemoryOperand(addr=0x{self.addr:X},is_mapped={self.is_mapped})'


@dataclass
class ImmediateOperand(Operand):
    """Represents an immediate operand (constant value)."""
    value: int

    def __repr__(self) -> str:
        return f'ImmediateOperand(value=0x{self.value:X})'

    def resolve_data_value(self) -> Union[str, int]:
        """Resolves the immediate value to a string or name if possible."""
        return extract_objc_string(self.value) or extract_c_cstring(self.value) or idc.get_name(self.value) or self.value


@dataclass
class DisplacementOperand(Operand):
    """Represents a displacement operand with a base register and an offset."""
    base: Register
    offset: int

    def __repr__(self) -> str:
        return f'DisplacementOperand(base={self.base}, offset=0x{self.offset:X})'


@dataclass
class IndexedDisplacementOperand(Operand):
    """Represents an operand with a base register, index register, and scale factor."""
    base: Register
    index: Register
    scale: int

    def __repr__(self) -> str:
        return f'IndexedDisplacementOperand(base={self.base}, index={self.index}, scale={self.scale})'


Operands = Union[
    IndexedDisplacementOperand, DisplacementOperand, ImmediateOperand, MemoryOperand, RegOperand, UnknownOperand]


@dataclass
class Instruction:
    """Represents a disassembled instruction."""
    ea: int
    size: int
    itype: int
    mnemonic: str
    operands: List[Operands] = field(default_factory=list)

    @staticmethod
    def from_ea(ea: int) -> Optional['Instruction']:
        """Decodes an instruction from the given address."""
        insn = ida_ua.insn_t()
        decoded_len = ida_ua.decode_insn(insn, ea)
        if decoded_len == 0:
            return None

        operands = [
            create_operand(op)
            for i, op in enumerate(insn.ops)
            if op.type != ida_ua.o_void
        ]

        return Instruction(
            ea=ea,
            size=insn.size,
            itype=insn.itype,
            mnemonic=idc.print_insn_mnem(ea),
            operands=operands,
        )

    def __repr__(self) -> str:
        ops_str = ', '.join(repr(op) for op in self.operands)
        return f'<Instruction 0x{self.ea:X} mnemonic="{self.mnemonic}" [{ops_str}]>'


def create_operand(op: ida_ua.op_t) -> Operands:
    """Creates an operand instance based on the operand type."""
    if op.type == ida_ua.o_reg:
        return RegOperand(reg=Register(op.reg))
    elif op.type in {ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near}:
        return MemoryOperand(addr=op.addr)
    elif op.type == ida_ua.o_imm:
        return ImmediateOperand(value=op.value)
    elif op.type == ida_ua.o_displ:
        base_reg = Register(op.phrase)
        if op.specflag1:
            index_reg = Register(op.specflag1)
            scale = 1 << op.specflag2
            return IndexedDisplacementOperand(base=base_reg, index=index_reg, scale=scale)
        else:
            return DisplacementOperand(base=base_reg, offset=op.addr)
    elif op.type == ida_ua.o_phrase:
        base_reg = Register(op.phrase)
        index_reg = Register(op.specflag1)
        scale = 1 << op.specflag2 if op.specflag2 else 1
        return IndexedDisplacementOperand(base=base_reg, index=index_reg, scale=scale)
    else:
        return UnknownOperand(op_type=op.type)
