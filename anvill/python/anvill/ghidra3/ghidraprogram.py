import anvill.ghidra3.remote_imports as rem_imp
from .remote_imports import *

from .ghidrafunction import *
from .ghidravariable import *
from .typecache import TypeCache

from typing import Final

from anvill.program import *
from anvill.arch import *
from anvill.os import *
from anvill.exc import *
from anvill.loc import *
from anvill.type import *

def get_os(currentProgram):
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

def get_arch(currentProgram):
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
        # create a flat api that we can pass along to not rely on globals
        flat_api = bridge.remote_eval('ghidra.program.flatapi.FlatProgramAPI(currentProgram)')
        Program.__init__(self,
                         get_arch(flat_api.currentProgram),
                         get_os(flat_api.currentProgram))
        self._bridge: Final[ghidra_bridge.GhidraBridge] = bridge
        self._api: Final[ghidra.program.flatapi.FlatProgramAPI] = flat_api
        self._type_cache: Final[TypeCache] = TypeCache(bridge)
    
    @property
    def type_cache(self):
        return self._type_cache

    def get_variable_impl(self, address):
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""
        print('get_variable_imp: {:#x}'.format(address))
        # TODO: this only returns data if the start addr is referenced
        data = self._api.getDataAt(self._api.toAddr(address))

        if data is None:
            raise InvalidVariableException("No data defined at {:x}".format(address))
            
        var_type = self.type_cache.get(data.dataType)
        if isinstance(data.dataType, rem_imp.ghidra_data.AbstractStringDataType):
            assert isinstance(var_type, ArrayType)
            var_type.set_num_elements(data.getLength())
        print('get_variable_imp returned: {:#x}'.format(address))
        return GhidraVariable(self._bridge, self._api, data, self._arch, address, var_type)

    def get_function_impl(self, address):
        """Given an architecture and an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""
        print('get_function_imp: {:#x}'.format(address))
        arch = self._arch

        addr = self._api.toAddr(address)
        g_func = self._api.getFunctionAt(addr)
        if not g_func:
            g_func = self._api.getFunctionContaining(addr)
        if not g_func:
            raise InvalidFunctionException(
                "No function defined at or containing address {:x}".format(address)
            )
        # if g_func.isThunk():
        #     return self.get_function_impl(
        #         g_func.getThunkedFunction(False).getEntryPoint().offset)

        func_type = self.type_cache.get(g_func)

        param_list = []
        for param in g_func.parameters:
            param_type = self.type_cache.get(param.dataType)
            loc = Location()
            loc.set_type(param_type)
            param_list.append(loc)

            if param.isRegisterVariable():
                loc.set_register(param.getRegister().name)
            else:
                raise NotImplementedError()
        
        ret_list = []
        retTy = self.type_cache.get(g_func.returnType)
        if not isinstance(retTy, VoidType):
            ret = g_func.getReturn()
            for reg in ret.getRegisters():
                loc = Location()
                loc.set_register(reg.name)
                loc.set_type(retTy)
                ret_list.append(loc)
        
        func = GhidraFunction(self._bridge, self._api, g_func, arch, address, param_list, ret_list, func_type)
        print('get_function_imp returned: {:#x}'.format(address))
        return func


    def get_symbols_impl(self, address):
        raise RuntimeError("TODO: NYI")
