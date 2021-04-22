from .remote_imports import *

from anvill.var import *
from anvill.exc import *
from anvill.type import *

class GhidraVariable(Variable):
    def __init__(self, bridge, flat_api, ghidra_var, arch, address, type_):
        super(GhidraVariable, self).__init__(arch, address, type_)
        self._ghidra_var = ghidra_var
        self._bridge = bridge
        self._api = flat_api

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
            addr = self._api.toAddr(ea)
            mb = self._api.getMemoryBlock(addr)
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
                # if it is unitialized, using 0 should be fine. Either the
                # program expects it to be zero initialized (likely), the program
                # overwrites the value at runtime with the real init value or
                # it is undefined and the program is broken
                bval = 0
            mem.map_byte(ea, bval, mb.isWrite(), mb.isExecute())
