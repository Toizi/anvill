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


def _get_address_sized_reg(arch, reg_name):
    """Given the regiseter name `reg_name`, find the name of the register in the
    same family whose size is the pointer size of this architecture."""

    try:
        family = arch.register_family(reg_name)
        addr_size = arch.pointer_size()
        for f_reg_name, f_reg_offset, f_reg_size in family:
            if 0 == f_reg_offset and addr_size == f_reg_size:
                return f_reg_name
    except:
        pass
    return arch.register_name(reg_name)


def _is_extern_seg(seg):
    """Returns `True` if `seg` refers to a segment with external variable or
    function declarations."""
    if not seg:
        return False

    seg_type = idc.get_segm_attr(seg.start_ea, idc.SEGATTR_TYPE)
    return seg_type == idc.SEG_XTRN


def _is_imported_table_seg(seg):
    """Returns `True` if `seg` refers to a segment that typically contains
    import entries, i.e. cross-reference pointers into an external segment."""
    if not seg:
        return False

    seg_name = idc.get_segm_name(seg.start_ea)
    return ".idata" in seg_name or ".plt" in seg_name or ".got" in seg_name


_OPERANDS_NUMS = (0, 1, 2)
_REF_OPERAND_TYPES = (
    idc.o_phrase,
    idc.o_displ,
    idc.o_imm,
    idc.o_far,
    idc.o_near,
    idc.o_mem,
)


def _add_real_xref(ea, ref_ea, out_ref_eas):
    """Sometimes IDA will have a operand like `[foo+10]` and the xref collector
    will give us the address of `foo`, but not the address of `foo+10`, so we
    will try to find it here."""
    global _OPERANDS_NUMS, _REF_OPERAND_TYPES

    ref_name = ida_name.get_ea_name(ref_ea)
    for i in _OPERANDS_NUMS:

        try:
            op_type = idc.get_operand_type(ea, i)
        except:
            return

        if op_type not in _REF_OPERAND_TYPES:
            continue

        op_str = idc.print_operand(ea, i)
        if op_str is None:
            return

        if ref_name in op_str:
            op_val = idc.get_operand_value(ea, i)
            out_ref_eas.add(op_val)


def _invent_var_type(ea, seg_ref, min_size=1):
    """Try to invent a variable type. This will basically be an array of bytes
    that spans what we need. We will, however, try to be slightly smarter and
    look for cross-references in the range, and when possible, use their types."""
    seg = find_segment_containing_ea(ea, seg_ref)
    if not seg:
        return ea, None

    head_ea = ida_bytes.get_item_head(ea)
    if head_ea < ea:
        head_seg = find_segment_containing_ea(head_ea, seg_ref)
        if head_seg != seg:
            return ea, None
        return _invent_var_type(head_ea, seg_ref, ea - head_ea)

    min_size = max(min_size, ida_bytes.get_item_size(ea))
    next_ea = ida_bytes.next_head(ea + 1, seg.end_ea)
    next_seg = find_segment_containing_ea(next_ea, seg_ref)

    arr = ArrayType()
    arr.set_element_type(IntegerType(1, False))

    if not next_seg or next_seg != seg:
        arr.set_num_elements(min_size)
        return ea, arr

    min_size = min(min_size, next_ea - ea)

    # TODO(pag): Go and do a better job, e.g. find pointers inside of the global.
    # i = 0
    # while i < min_size:
    #   for ref_ea in _xref_generator(ea + i, seg_ref):
    #     break
    #   i += 1

    arr.set_num_elements(min_size)
    return ea, arr


def _visit_ref_ea(program, ref_ea, add_refs_as_defs):
    """Try to add `ref_ea` as some referenced entity."""
    if not program.try_add_referenced_entity(ref_ea, add_refs_as_defs):
        seg_ref = [None]
        seg = find_segment_containing_ea(ref_ea, seg_ref)
        if seg:
            print("Unable to add {:x} as a variable or function".format(ref_ea))