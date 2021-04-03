# for auto-complete,
# requires https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
# Only works if this module is not called `ghidra.py`
try:
    import ghidra
    from ghidra.ghidra_builtins import *
except:
    pass

from typing import Final, Union, List, Tuple, Optional, Set

import ghidra_bridge

from .arch import *
from .exc import *
from .function import *
from .loc import *
from .os import *
from .type import *
from .program import *
from .util import *

def get_os():
    # I don't think ghidra has a notion of target os so we use the executable
    # format as a replacement.
    # Since we are using this information mostly to get default calling
    # conventions, ghidra has the CompilerSpec class that could be used instead.
    # > currentProgram.getCompilerSpec().getDefaultCallingConvention()
    exe_format = currentProgram.getExecutableFormat()
    if exe_format == 'Portable Executable (PE)':
        return WindowsOS()
    if exe_format == 'Executable and Linking Format (ELF)':
        return LinuxOS()
    if exe_format == 'Mac OS X Mach-O':
        return MacOS()
    
    raise UnhandledOSException(
        "Missing operating system object type for executable format '{}'"
            .format(exe_format)
    )

def get_arch():
    lang_id = str(currentProgram.getLanguageID())
    proc, endianess, bitness, compiler_maybe = lang_id.split(':')
    if proc == 'x86':
        if bitness == '32':
            return X86Arch()
        elif bitness == '64':
            return AMD64Arch()
    elif proc == 'AARCH64':
        return AArch64Arch()
    elif proc == 'ARM':
        return AArch32Arch()

    raise UnhandledArchitectureType(
        "Missing architecture object type for language id '{}'".format(lang_id)
    )



class GhidraProgram(Program):
    def __init__(self, bridge):
        Program.__init__(self, get_arch(), get_os())
        self._bridge: Final[ghidra_bridge.GhidraBridge] = bridge

    def get_variable_impl(self, address):
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""
        raise RuntimeError("TODO: NYI")

    def get_function_impl(self, address):
        """Given an architecture and an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""
        raise RuntimeError("TODO: NYI")

    def get_symbols_impl(self, address):
        raise RuntimeError("TODO: NYI")



def get_ghidra_program(b : ghidra_bridge.GhidraBridge):
    # import the flat ghidra api into the current global namespace
    b.get_flat_api(namespace=globals())
    prog = GhidraProgram(b)
    return prog
