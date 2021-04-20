import anvill.ghidra3.remote_imports as rem_imp
from anvill.type import *
from anvill.exc import *
from anvill.function import *

from jfx_bridge import bridge

class TypeCache:
    """The class provides API to recursively visit the ghidra types and convert
    them to the anvill `Type` instance. It maintains a cache of visited ghidra
    types to reduce lookup time.
    """

    __slots__ = ("_bridge", "_cache")

    # list of unhandled type classes which should log error
    _err_type_class = {
        # bn.TypeClass.VarArgsTypeClass: "VarArgsTypeClass",
        # bn.TypeClass.ValueTypeClass: "ValueTypeClass",
        # bn.TypeClass.WideCharTypeClass: "WideCharTypeClass",
    }

    def __init__(self, bridge):
        # self._bv = bv
        self._cache = dict()
        self._bridge = bridge

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

        assert bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.Pointer)

        ret = PointerType()
        self._cache[self._cache_key(data_type)] = ret
        ret.set_element_type(self._convert_ghidra_type(data_type.getDataType()))
        return ret

    def _convert_function(self, func) -> Type:
        """ Convert ghidra function signature type into a `Type` instance"""

        assert bridge.bridged_isinstance(func, rem_imp.ghidra_listing.Function)

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

        assert bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.AbstractIntegerDataType)
        return IntegerType(data_type.getLength(), data_type.isSigned())
    
    def _convert_string(self, data_type) -> Type:
        """ Convert ghidra string type into a `Type` instance"""

        assert bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.AbstractStringDataType)
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

        assert bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.DefaultDataType)
        return IntegerType(data_type.getLength(), False)
    
    def _convert_undefined(self, data_type) -> Type:
        """ Convert ghidra undefined type into a `Type` instance"""

        assert bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.Undefined)
        return IntegerType(data_type.getLength(), False)


    def _convert_ghidra_type(self, data_type) -> Type:
        """Convert an ghidra `DataType|Function` instance into an anvill `Type` instance."""

        if self._cache_key(data_type) in self._cache:
            return self._cache[self._cache_key(data_type)]
        
        # Void type
        if data_type is None or bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.VoidDataType):
            return VoidType()
        
        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.DefaultDataType):
            return self._convert_default(data_type)
        
        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.Undefined):
            return self._convert_undefined(data_type)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.Pointer):
            return self._convert_pointer(data_type)

        # if isinstance(data_type, rem_imp.ghidra_data.FunctionDefinitionDataType):
        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_listing.Function):
            return self._convert_function(data_type)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.ArrayDataType):
            return self._convert_array(data_type)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.StructureDataType):
            return self._convert_struct(data_type)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.EnumDataType):
            return self._convert_enum(data_type)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.BooleanDataType):
            return BoolType()

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.AbstractIntegerDataType):
            return self._convert_integer(data_type)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.AbstractFloatDataType):
            return FloatingPointType(data_type.width)

        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.TypedefDataType):
            return self._convert_named_reference(data_type)
        
        if bridge.bridged_isinstance(data_type, rem_imp.ghidra_data.AbstractStringDataType):
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

        elif bridge.bridged_isinstance(ty, rem_imp.ghidra_data.DataType):
            return self._convert_ghidra_type(ty)
        elif bridge.bridged_isinstance(ty, rem_imp.ghidra_listing.Function):
            return self._convert_ghidra_type(ty)
        elif not ty:
            return VoidType()

        print(f'type of {ty} is {type(ty)}')

        raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)
