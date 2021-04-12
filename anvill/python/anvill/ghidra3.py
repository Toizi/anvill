# for auto-complete,
# requires https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
# Only works if this module is not called `ghidra.py`
try:
    import ghidra
    from ghidra.ghidra_builtins import *
    ghidra_data = ghidra.program.model.data
    ghidra_listing = ghidra.program.model.listing
    ghidra_decomp = ghidra.app.decompiler
    ghidra_block = ghidra.program.model.block
except:
    pass

# modules that will be imported into the global name space
remote_imports = [
    ('ghidra.program.model.data', 'ghidra_data'),
    ('ghidra.program.model.listing', 'ghidra_listing'),
    ('ghidra.app.decompiler', 'ghidra_decomp'),
    ('ghidra.program.model.block', 'ghidra_block'),
]

from typing import Final, Union, List, Tuple, Optional, Set
from types import FunctionType

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


class TypeCache:
    """The class provides API to recursively visit the ghidra types and convert
    them to the anvill `Type` instance. It maintains a cache of visited ghidra
    types to reduce lookup time.
    """

    __slots__ = (#"_bv",
    "_cache")

    # list of unhandled type classes which should log error
    _err_type_class = {
        # bn.TypeClass.VarArgsTypeClass: "VarArgsTypeClass",
        # bn.TypeClass.ValueTypeClass: "ValueTypeClass",
        # bn.TypeClass.WideCharTypeClass: "WideCharTypeClass",
    }

    def __init__(self):
        # self._bv = bv
        self._cache = dict()

    def _cache_key(self, data_type):
        """ Convert bn Type instance to cache key"""
        return str(data_type)

    # def _convert_struct(self, data_type: bn.types.Type) -> Type:
    #     """Convert bn struct type into a `Type` instance"""

    #     assert data_type.type_class == bn.TypeClass.StructureTypeClass

    #     if data_type.structure.type == bn.StructureType.UnionStructureType:
    #         return self._convert_union(data_type)

    #     assert (
    #         data_type.structure.type == bn.StructureType.StructStructureType
    #         or data_type.structure.type == bn.StructureType.ClassStructureType
    #     )

    #     ret = StructureType()
    #     self._cache[self._cache_key(data_type)] = ret
    #     for elem in data_type.structure.members:
    #         ret.add_element_type(self._convert_bn_type(elem.type))

    #     return ret

    # def _convert_union(self, data_type: bn.types.Type) -> Type:
    #     """Convert bn union type into a `Type` instance"""

    #     assert data_type.structure.type == bn.StructureType.UnionStructureType

    #     ret = UnionType()
    #     self._cache[self._cache_key(data_type)] = ret
    #     for elem in data_type.structure.members:
    #         ret.add_element_type(self._convert_bn_type(elem.type))

    #     return ret

    # def _convert_enum(self, data_type: bn.types.Type) -> Type:
    #     """Convert bn enum type into a `Type` instance"""

    #     assert data_type.type_class == bn.TypeClass.EnumerationTypeClass

    #     ret = EnumType()
    #     self._cache[self._cache_key(data_type)] = ret
    #     # The underlying type of enum will be an Interger of size info.width
    #     ret.set_underlying_type(IntegerType(data_type.width, False))
    #     return ret

    # def _convert_typedef(self, data_type: bn.types.Type) -> Type:
    #     """ Convert bn typedef into a `Type` instance"""

    #     assert data_type.type_class == bn.NamedTypeReferenceClass.TypedefNamedTypeClass

    #     ret = TypedefType()
    #     self._cache[self._cache_key(data_type)] = ret
    #     ret.set_underlying_type(
    #         self._convert_bn_type(self._bv.get_type_by_name(data_type.name))
    #     )
    #     return ret

    # def _convert_array(self, data_type: bn.types.Type) -> Type:
    #     """ Convert bn pointer type into a `Type` instance"""

    #     assert data_type.type_class == bn.TypeClass.ArrayTypeClass

    #     ret = ArrayType()
    #     self._cache[self._cache_key(data_type)] = ret
    #     ret.set_element_type(self._convert_bn_type(data_type.element_type))
    #     ret.set_num_elements(data_type.count)
    #     return ret

    def _convert_pointer(self, data_type) -> Type:
        """ Convert ghidra pointer type into a `Type` instance"""

        assert isinstance(data_type, ghidra_data.Pointer)

        ret = PointerType()
        self._cache[self._cache_key(data_type)] = ret
        ret.set_element_type(self._convert_ghidra_type(data_type.getDataType()))
        return ret

    def _convert_function(self, func) -> Type:
        """ Convert ghidra function signature type into a `Type` instance"""

        assert isinstance(func, ghidra_listing.Function)

        sig = func.getSignature()
        ret = FunctionType()
        self._cache[self._cache_key(sig)] = ret
        ret.set_return_type(self._convert_ghidra_type(sig.getReturnType()))

        for arg in sig.getArguments():
            ret.add_parameter_type(self._convert_ghidra_type(arg.getDataType()))

        if func.hasVarArgs():
            ret.set_is_variadic()

        return ret

    def _convert_integer(self, data_type) -> Type:
        """ Convert ghidra integer type into a `Type` instance"""

        assert isinstance(data_type, ghidra_data.AbstractIntegerDataType)
        return IntegerType(data_type.getLength(), data_type.isSigned())
    
    def _convert_string(self, data_type) -> Type:
        """ Convert ghidra string type into a `Type` instance"""

        assert isinstance(data_type, ghidra_data.AbstractStringDataType)
        typ = ArrayType()
        typ.set_element_type(self._convert_ghidra_type(data_type.getReplacementBaseType()))
        # cannot set length here since the data type has no reference to the
        # actual piece of data
        return typ


    # def _convert_named_reference(self, data_type: bn.types.Type) -> Type:
    #     """ Convert named type references into a `Type` instance"""

    #     assert data_type.type_class == bn.TypeClass.NamedTypeReferenceClass

    #     named_data_type = data_type.named_type_reference
    #     ref_type = self._bv.get_type_by_name(named_data_type.name)
    #     if named_data_type.type_class == bn.NamedTypeReferenceClass.StructNamedTypeClass:
    #         return self._convert_struct(ref_type)

    #     elif named_data_type.type_class == bn.NamedTypeReferenceClass.UnionNamedTypeClass:
    #         return self._convert_union(ref_type)

    #     elif named_data_type.type_class == bn.NamedTypeReferenceClass.TypedefNamedTypeClass:
    #         return self._convert_typedef(named_data_type)

    #     elif named_data_type.type_class == bn.NamedTypeReferenceClass.EnumNamedTypeClass:
    #         return self._convert_enum(ref_type)

    #     else:
    #         DEBUG("WARNING: Unknown named type {} not handled".format(named_data_type))
    #         return VoidType()
    def _convert_default(self, data_type) -> Type:
        """ Convert ghidra default (undefined) type into a `Type` instance"""

        assert isinstance(data_type, ghidra_data.DefaultDataType)
        return IntegerType(data_type.getLength(), False)
    
    def _convert_undefined(self, data_type) -> Type:
        """ Convert ghidra undefined type into a `Type` instance"""

        assert isinstance(data_type, ghidra_data.Undefined)
        return IntegerType(data_type.getLength(), False)


    def _convert_ghidra_type(self, data_type) -> Type:
        """Convert an ghidra `DataType|Function` instance into an anvill `Type` instance."""

        if self._cache_key(data_type) in self._cache:
            return self._cache[self._cache_key(data_type)]
        
        # Void type
        if data_type is None or isinstance(data_type, ghidra_data.VoidDataType):
            return VoidType()
        
        if isinstance(data_type, ghidra_data.DefaultDataType):
            return self._convert_default(data_type)
        
        if isinstance(data_type, ghidra_data.Undefined):
            return self._convert_undefined(data_type)

        if isinstance(data_type, ghidra_data.Pointer):
            return self._convert_pointer(data_type)

        # if isinstance(data_type, ghidra_data.FunctionDefinitionDataType):
        if isinstance(data_type, ghidra_listing.Function):
            return self._convert_function(data_type)

        if isinstance(data_type, ghidra_data.ArrayDataType):
            return self._convert_array(data_type)

        if isinstance(data_type, ghidra_data.StructureDataType):
            return self._convert_struct(data_type)

        if isinstance(data_type, ghidra_data.EnumDataType):
            return self._convert_enum(data_type)

        if isinstance(data_type, ghidra_data.BooleanDataType):
            return BoolType()

        if isinstance(data_type, ghidra_data.AbstractIntegerDataType):
            return self._convert_integer(data_type)

        if isinstance(data_type, ghidra_data.AbstractFloatDataType):
            return FloatingPointType(data_type.width)

        if isinstance(data_type, ghidra_data.TypedefDataType):
            return self._convert_named_reference(data_type)
        
        if isinstance(data_type, ghidra_data.AbstractStringDataType):
            return self._convert_string(data_type)

        # if data_type.type_class in TypeCache._err_type_class.keys():
        #     DEBUG(
        #         "WARNING: Unhandled type class {}".format(
        #             TypeCache._err_type_class[data_type.type_class]
        #         )
        #     )
        #     return VoidType()

        raise UnhandledTypeException("Unhandled type: {}".format(str(data_type)), data_type)

    def get(self, ty) -> Type:
        """Type class that gives access to type sizes, printings, etc."""

        if isinstance(ty, Type):
            return ty

        elif isinstance(ty, Function):
            return ty.type()

        elif isinstance(ty, ghidra_data.DataType):
            return self._convert_ghidra_type(ty)
        elif isinstance(ty, ghidra_listing.Function):
            return self._convert_ghidra_type(ty)
        elif not ty:
            return VoidType()

        raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)

class GhidraVariable(Variable):
    def __init__(self, bridge, ghidra_var, arch, address, type_):
        super(GhidraVariable, self).__init__(arch, address, type_)
        self._ghidra_var = ghidra_var
        self._bridge = bridge

    def visit(self, program, is_definition, add_refs_as_defs):
        if not is_definition:
            return
        print('GhidraVariable.visit')

        # type could be None if type class not handled
        if self._type is None:
            return

        if isinstance(self._type, VoidType):
            return

        begin = self._address
        end = begin + self._type.size(self._arch)
        mem = program.memory()

        # TODO: might have to move this to remote function entirely for perf
        for ea in range(begin, end):
            addr = toAddr(ea)
            mb = getMemoryBlock(addr)
            if mb is None:
                continue

            # variable might be uninitialized
            # ghidra exceptions don't inherit from the base exception class
            # therefore we cannot catch them here
            try:
                bval = mb.getByte(addr)
            except KeyboardInterrupt:
                raise
            except:
                # TODO: what should we do if the data is in an uninitialized segment
                continue
            mem.map_byte(ea, bval, mb.isWrite(), mb.isExecute())


class GhidraFunction(Function):
    def __init__(self, bridge, ghidra_func, arch, address, param_list, ret_list, func_type):
        super(GhidraFunction, self).__init__(arch, address, param_list, ret_list, func_type)
        self._g_func : ghidra.program.model.listing.Function = ghidra_func
        self._bridge :ghidra_bridge.GhidraBridge = bridge
    
    def name(self):
        return self._g_func.name
    
    def visit(self, program, is_definition, add_refs_as_defs):
        # TODO: is_definition is either always true or false,
        # depending on the cmdline arg
        # Shouldn't there be some logic that decides based on whether the function
        # is an import if this is a definition and should be properly included,
        # i.e. record all instruction bytes, and get references from the function
        # itself
        if not is_definition:
            return

        # record the memory of the function
        mem = program.memory()
        for addr_set in self._g_func.getBody():
            ea_start = addr_set.getMinAddress()
            ea_end = addr_set.getMaxAddress()

            # thunk functions don't have start == end
            if ea_start == ea_end:
                continue

            # fast path, whole address set has the same permissions
            mb = getMemoryBlock(ea_start)
            if mb.contains(ea_end):
                writable = mb.isWrite()
                executable = mb.isExecute()
                ea_start_int = ea_start.offset
                remote_eval_str = '[mb.getByte(ea) for ea in addr_set]'
                for i, val in enumerate(self._bridge.remote_eval(remote_eval_str,
                                                       addr_set=addr_set, mb=mb)):
                    mem.map_byte(ea_start_int + i, val, writable, executable)
            else:
                raise NotImplementedError('TODO: Implement slow path')

        # now find any references that we need to record from this function
        bbm = ghidra_block.BasicBlockModel(currentProgram)
        blocks = bbm.getCodeBlocksContaining(self._g_func.getBody(), None)
        while blocks.hasNext():
            bb = blocks.next()
            ea_start = bb.getMinAddress()
            ea_end = bb.getMaxAddress()

            instrs = get_instructions_in_range(ea_start, ea_end)
            for instr in instrs:
                # for ref in instr.getReferencesFrom():
                ft = instr.getFlowType()
                if ft.isCall():
                    program.try_add_referenced_entity(instr.getFlows()[0].offset, add_refs_as_defs)
                elif ft.isJump():
                    # TODO: tail calls
                    pass
                else:
                    for ref in instr.getReferencesFrom():
                        if ref.isStackReference():
                            continue

                        program.try_add_referenced_entity(ref.getToAddress().offset, add_refs_as_defs)
                        


        # pcode decompilation feels like it is too low level since we now need
        # to handle all of the pcode references ourselves
        # the advantages of this approach is that the decompiler has already
        # removed dead code
        # decomp_result = decomp_function(self._g_func)
        # for op in decomp_result_get_pcode(decomp_result):
        #     print(op)
        #     if op.getOpcode() == op.CALL:
        #         for in_var in op.getInputs():
        #             program.try_add_referenced_entity(in_var.getAddress().offset, add_refs_as_defs)
        #     if op.getOpcode() == op.LOAD:
        #         program.try_add_referenced_entity(op.getInput(0).getAddress().offset, add_refs_as_defs)


            # instrs = get_instructions_in_range(ea_start, ea_end)
            # for instr in instrs:
            #     # control flows other than fallthrough
            #     # for flow in instr.getFlows():



            #     print('{: >8x}: {}'.format(instr.getAddress().offset, instr))
            #     for ref in instr.getReferencesFrom():
            #         if ref.isStackReference():
            #             continue
            #         print('{} has reference to {:#x}'.format(instr, ref.getToAddress().offset))
            #         program.try_add_referenced_entity(ref.getToAddress().offset, add_refs_as_defs)
        

def get_instructions_in_range(ea_start, ea_end):
    instrs = []
    inst = getInstructionAt(ea_start)
    while inst and inst.address <= ea_end:
        instrs.append(inst)
        inst = getInstructionAfter(inst)
    return instrs

def decomp_function(ghidra_func, timeout=30):
    global NORMALIZING_DECOMPILER
    ifc = globals().get('NORMALIZING_DECOMPILER', None)
    if ifc:
        return ifc.decompileFunction(ghidra_func, timeout, None)

    options = ghidra_decomp.DecompileOptions()
    ifc = ghidra_decomp.DecompInterface()
    ifc.setOptions(options)

    ifc.openProgram(currentProgram)
    ifc.setSimplificationStyle('normalize')

    globals()['NORMALIZING_DECOMPILER'] = ifc
    return decomp_function(ghidra_func, timeout)

def decomp_result_get_pcode(decomp_result):# -> List[ghidra.program.model.pcode.PcodeOp]:
    high = decomp_result.getHighFunction()
    return list(high.getPcodeOps())

class GhidraProgram(Program):
    def __init__(self, bridge):
        Program.__init__(self, get_arch(), get_os())
        self._bridge: Final[ghidra_bridge.GhidraBridge] = bridge
        self._type_cache: Final[TypeCache] = TypeCache()
    
    @property
    def type_cache(self):
        return self._type_cache

    def get_variable_impl(self, address):
        """Given an address, return a `Variable` instance, or
        raise an `InvalidVariableException` exception."""
        print('get_variable_imp: {:#x}'.format(address))
        # TODO: this only returns data if the start addr is referenced
        data = getDataAt(toAddr(address))

        if data is None:
            raise InvalidVariableException("No data defined at {:x}".format(address))
            
        var_type = self.type_cache.get(data.dataType)
        if isinstance(data.dataType, ghidra_data.AbstractStringDataType):
            assert isinstance(var_type, ArrayType)
            var_type.set_num_elements(data.getLength())
        print('get_variable_imp returned: {:#x}'.format(address))
        return GhidraVariable(self._bridge, data, self._arch, address, var_type)

    def get_function_impl(self, address):
        """Given an architecture and an address, return a `Function` instance or
        raise an `InvalidFunctionException` exception."""
        print('get_function_imp: {:#x}'.format(address))
        arch = self._arch

        addr = toAddr(address)
        g_func = getFunctionAt(addr)
        if not g_func:
            g_func = getFunctionContaining(addr)
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
        
        func = GhidraFunction(self._bridge, g_func, arch, address, param_list, ret_list, func_type)
        print('get_function_imp returned: {:#x}'.format(address))
        return func


    def get_symbols_impl(self, address):
        raise RuntimeError("TODO: NYI")

def import_remote_modules(b : ghidra_bridge.GhidraBridge):
    for module_path, import_as in remote_imports:
        globals()[import_as] = b.remote_import(module_path)

def remotify(bridge, func_name):
    # get "local" function implementation
    func = globals()[func_name]
    # must be a remote callable already?
    if not isinstance(func, FunctionType):
        return
    # get a remote handle to this function
    new_func = bridge.remoteify(func)
    # overwrite old function with remote function
    globals()[func_name] = new_func


def get_ghidra_program(b : ghidra_bridge.GhidraBridge):
    # import the flat ghidra api into the current global namespace
    b.get_flat_api(namespace=globals())
    remotify(b, 'get_instructions_in_range')
    remotify(b, 'decomp_function')
    remotify(b, 'decomp_result_get_pcode')
    import_remote_modules(b)
    prog = GhidraProgram(b)
    return prog
