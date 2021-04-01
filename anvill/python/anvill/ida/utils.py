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


import ida_segment
import idc


TYPE_CONTEXT_NESTED = 0
TYPE_CONTEXT_GLOBAL_VAR = 1
TYPE_CONTEXT_FUNCTION = 2
TYPE_CONTEXT_PARAMETER = 3
TYPE_CONTEXT_RETURN = 4


def find_segment_containing_ea(ea, seg_ref):
    """Find and return a `segment_t` containing `ea`, or `None`."""
    seg = seg_ref[0]
    if seg and seg.contains(ea):
        return seg

    seg = ida_segment.get_first_seg()
    while seg:
        seg_ref[0] = seg
        if seg.contains(ea):
            return seg
        seg = ida_segment.get_next_seg(seg.start_ea)

    return None


def is_imported_table_seg(seg):
    """Returns `True` if `seg` refers to a segment that typically contains
    import entries, i.e. cross-reference pointers into an external segment."""
    if not seg:
        return False

    seg_name = idc.get_segm_name(seg.start_ea)
    return ".idata" in seg_name or ".plt" in seg_name or ".got" in seg_name
