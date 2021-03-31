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


TYPE_CONTEXT_NESTED = 0
TYPE_CONTEXT_GLOBAL_VAR = 1
TYPE_CONTEXT_FUNCTION = 2
TYPE_CONTEXT_PARAMETER = 3
TYPE_CONTEXT_RETURN = 4


_FLOAT_SIZES = (2, 4, 8, 10, 12, 16)


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
