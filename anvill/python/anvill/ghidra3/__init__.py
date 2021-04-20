
import ghidra_bridge
from .ghidraprogram import GhidraProgram
from .remote_imports import init as imports_init

def get_ghidra_program(b : ghidra_bridge.GhidraBridge):
    imports_init(b)
    prog = GhidraProgram(b)
    return prog