import anvill.ghidra3.remote_imports as rem_imp
from .remote_imports import *

import ghidra_bridge

from .ghidrafunction import *

from anvill.function import *
from anvill.exc import *

class GhidraFunction(Function):
    def __init__(self, bridge, flat_api, ghidra_func, arch, address, param_list, ret_list, func_type):
        super(GhidraFunction, self).__init__(arch, address, param_list, ret_list, func_type)
        self._g_func : ghidra.program.model.listing.Function = ghidra_func
        self._bridge :ghidra_bridge.GhidraBridge = bridge
        self._api = flat_api
    
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
        mem = program.memory
        for addr_set in self._g_func.getBody():
            ea_start = addr_set.getMinAddress()
            ea_end = addr_set.getMaxAddress()

            # thunk functions don't have start == end
            if ea_start == ea_end:
                continue

            # fast path, whole address set has the same permissions
            mb = self._api.getMemoryBlock(ea_start)
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
        bbm = rem_imp.ghidra_block.BasicBlockModel(self._api.currentProgram)
        blocks = bbm.getCodeBlocksContaining(self._g_func.getBody(), None)
        while blocks.hasNext():
            bb = blocks.next()
            ea_start = bb.getMinAddress()
            ea_end = bb.getMaxAddress()

            instrs = rem_imp.get_instructions_in_range(ea_start, ea_end)
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
        