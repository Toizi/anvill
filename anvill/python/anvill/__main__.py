#!/usr/bin/env python3

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

import os
import sys
import argparse
import json
import platform
import typing

from .util import config_logger
from .util import DEBUG


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("--bin_in", help="Path to input binary.", required=True)

    arg_parser.add_argument(
        "--spec_out", help="Path to output JSON specification.", required=True
    )

    arg_parser.add_argument(
        "--entry_point",
        type=str,
        help="Output functions only reachable from given entry point.",
    )

    arg_parser.add_argument(
        "--refs_as_defs",
        action="store_true",
        help="Output definitions of discovered functions and variables.",
        default=False,
    )

    arg_parser.add_argument(
        "--log_file",
        type=str,
        default=None,
        help="Log to a specific file.",
    )

    arg_parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug log for the module",
    )

    arg_parser.add_argument(
        "--base_address",
        type=str,
        help="Where the image should be loaded, expressed as an hex integer.",
    )

    arg_parser.add_argument(
        "--analyzer",
        type=str,
        choices=["binja", "ghidra"],
        default="binja",
        help="Analyzer framework to use"
    )

    arg_parser.add_argument(
        "--readable",
        action='store_true',
        help="Whether the output json will be formatted with indentation"
    )

    arg_parser.add_argument(
        "--shutdown-ghidra-bridge",
        action='store_true',
        help="Shut down the ghidra bridge after execution"
    )

    args = arg_parser.parse_args()

    # Configure logger
    config_logger(args.log_file, args.verbose)

    maybe_base_address: Optional[int] = None
    if args.base_address is not None:
        try:
            maybe_base_address = int(args.base_address, 16)
            DEBUG(
                f"Binary Ninja will attempt to load the image at virtual address {hex(maybe_base_address)}"
            )

        except:
            ERROR(f"The specified address it not valid: '{hex(args.base_address)}'")
            return 1

    p = get_program(args.bin_in, maybe_base_address)
    if p is None:
        sys.stderr.write("FATAL: Could not initialize BinaryNinja's BinaryView\n")
        sys.stderr.write("Does BinaryNinja support this architecture?\n")
        sys.exit(1)

    if args.analyzer == "binja":
        p = binja_main(args)
    else:
        p = ghidra_main(args)

    # an error occurred
    if isinstance(p, int):
        return p

    open(args.spec_out, "w").write(
        json.dumps(p.proto(), indent=args.readable and 2 or None)
    )


def binja_main(args):
    import binaryninja as bn
    from .binja import get_program

    bv = p.bv

    is_macos = "darwin" in platform.system().lower()

    ep = None
    if args.entry_point is not None:
        try:
            ep = int(args.entry_point, 0)
        except ValueError:
            ep = args.entry_point

    ep_ea = None

    if ep is None:
        for f in bv.functions:
            ea = f.start
            DEBUG(f"Looking at binja found function at: {ea:x}")
            p.add_function_definition(ea, args.refs_as_defs)
    elif isinstance(ep, int):
        p.add_function_definition(ep, args.refs_as_defs)
    else:
        for s in bv.get_symbols():
            ea, name = s.address, s.name
            if name == ep:
                ep_ea = ea
                break

        # On macOS, we often have underscore-prefixed names, e.g. `_main`, so
        # with `--entry_point main` we really want to find `_main`, but lift it
        # as `main`.
        if ep_ea is None and is_macos:
            underscore_ep = "_{}".format(ep)
            for s in bv.get_symbols():
                ea, name = s.address, s.name
                if name == underscore_ep:
                    ep_ea = ea
                    break

        if ep_ea is not None:
            p.add_function_definition(ep_ea, args.refs_as_defs)
            p.add_symbol(ep_ea, ep)  # Add the name from `--entry_point`.
        else:
            return 1  # Failed to find the entrypoint.

    for s in bv.get_symbols():
        ea, name = s.address, s.name
        if ea != ep_ea:
            p.add_symbol(ea, name)

    return p

if typing.TYPE_CHECKING:
    try:
        import ghidra
        from ghidra.ghidra_builtins import *
    except:
        pass

def ghidra_main(args):
    from .ghidra3 import get_ghidra_program
    import ghidra_bridge

    try:
        bridge = ghidra_bridge.GhidraBridge(namespace=globals())
    except ConnectionRefusedError:
        print("error: Could not establish ghidra bridge connection.")
        print("Make sure you have a ghidra project open and the bridge running")
        return 1
    except:
        raise


    with bridge as b:

        try:
            p = get_ghidra_program(b)

            ep = None
            if args.entry_point is not None:
                try:
                    ep = int(args.entry_point, 0)
                except ValueError:
                    ep = args.entry_point

            ep_ea = None

            if ep is None:
                for f in bridge.remote_eval('currentProgram.getFunctionManager().getFunctions(True)'):
                    ea = f.getEntryPoint().offset
                    p.add_function_definition(ea, args.refs_as_defs)
            elif isinstance(ep, int):
                p.add_function_definition(ep, args.refs_as_defs)
            else:
                func = getFunction(ep)
                if func is None:
                    print('error: Could not find entry point with name {}'.format(ep))
                    return 1
                p.add_function_definition(func.getEntryPoint().offset, args.refs_as_defs)

            # remote eval for potentially large collections. Very slow otherwise
            for ea, name in bridge.remote_eval("""[(s.getAddress().offset, s.getName()) for s in
                                            currentProgram.getSymbolTable().getAllSymbols(False)]"""):
                if ea != ep_ea:
                    p.add_symbol(ea, name)

        except:
            if args.shutdown_ghidra_bridge:
                b.remote_shutdown()
            raise

        if args.shutdown_ghidra_bridge:
            b.remote_shutdown()
        return p



if __name__ == "__main__":
    exit(main())
