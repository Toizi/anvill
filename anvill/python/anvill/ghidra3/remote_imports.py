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

import ghidra_bridge
from types import FunctionType

# modules that will be imported into the global name space
remote_imports = [
    ('ghidra.program.model.data', 'ghidra_data'),
    ('ghidra.program.model.listing', 'ghidra_listing'),
    ('ghidra.app.decompiler', 'ghidra_decomp'),
    ('ghidra.program.model.block', 'ghidra_block'),
    ('ghidra.program.database.function', 'ghidra_db_function'),
]

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


def init(b):
    remotify(b, 'get_instructions_in_range')
    remotify(b, 'decomp_function')
    remotify(b, 'decomp_result_get_pcode')
    import_remote_modules(b)


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
