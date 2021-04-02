# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import binaryninja as bn


class XrefType:
    XREF_NONE = 0
    XREF_IMMEDIATE = 1
    XREF_DISPLACEMENT = 2
    XREF_MEMORY = 3
    XREF_CONTROL_FLOW = 4

    @staticmethod
    def is_memory(bv, reftype):
        return reftype in (XrefType.XREF_DISPLACEMENT, XrefType.XREF_MEMORY)


def collect_xrefs_from_inst(bv, inst, ref_eas, reftype=XrefType.XREF_NONE):
    """Recursively collect xrefs in a IL instructions"""
    if not isinstance(inst, bn.LowLevelILInstruction):
        return

    if is_unimplemented(bv, inst) or is_undef(bv, inst):
        return

    if is_function_call(bv, inst) or is_jump(bv, inst):
        reftype = XrefType.XREF_CONTROL_FLOW

    elif is_memory_inst(bv, inst) or is_unimplemented_mem(bv, inst):
        mem_il = inst.dest if is_store_inst(bv, inst) else inst.src

        if is_constant(bv, mem_il):
            reftype = XrefType.XREF_MEMORY
        else:
            reftype = XrefType.XREF_DISPLACEMENT

        collect_xrefs_from_inst(bv, mem_il, ref_eas, reftype)

        for opnd in inst.operands:
            collect_xrefs_from_inst(bv, opnd, ref_eas)

    elif is_constant_pointer(bv, inst):
        const_ea = inst.constant
        if is_code(bv, const_ea) and not XrefType.is_memory(bv, reftype):
            ref_eas.add(const_ea)
        elif is_data(bv, const_ea):
            ref_eas.add(const_ea)

    # Recursively look for the xrefs in operands
    for opnd in inst.operands:
        collect_xrefs_from_inst(bv, opnd, ref_eas, reftype)


def is_valid_addr(bv, addr):
    return bv.get_segment_at(addr) is not None


def is_constant(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_CONST,
        bn.LowLevelILOperation.LLIL_CONST_PTR,
    )


def is_constant_pointer(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_CONST_PTR


def is_function_call(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_CALL,
        bn.LowLevelILOperation.LLIL_TAILCALL,
        bn.LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
    )


def is_tailcall(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_TAILCALL


def is_return(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_RET


def is_jump(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_JUMP,
        bn.LowLevelILOperation.LLIL_JUMP_TO,
    )


def is_branch(bv, inst):
    return inst.operation in (
        bn.LowLevelILOperation.LLIL_JUMP,
        bn.LowLevelILOperation.LLIL_JUMP_TO,
        bn.LowLevelILOperation.LLIL_GOTO,
    )


def is_load_inst(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_LOAD


def is_store_inst(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_STORE


def is_memory_inst(bv, inst):
    return is_load_inst(bv, inst) or is_store_inst(bv, inst)


def is_unimplemented(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_UNIMPL


def is_unimplemented_mem(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_UNIMPL_MEM


def is_undef(bv, inst):
    return inst.operation == bn.LowLevelILOperation.LLIL_UNDEF


def is_code(bv, addr):
    for sec in bv.get_sections_at(addr):
        if sec.start <= addr < sec.end:
            return sec.semantics == bn.SectionSemantics.ReadOnlyCodeSectionSemantics
    return False


def is_data(bv, addr):
    for sec in bv.get_sections_at(addr):
        if sec.start <= addr < sec.end:
            return (
                sec.semantics == bn.SectionSemantics.ReadOnlyDataSectionSemantics
                or sec.semantics == bn.SectionSemantics.ReadWriteDataSectionSemantics
            )
    return False
