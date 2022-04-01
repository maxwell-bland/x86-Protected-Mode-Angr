import angr
import cle
import claripy
import IPython
from iced_x86 import *
from types import ModuleType
from typing import Dict, Sequence

def dt_lookup(state, sel, offset, base=None):
    # Protected mode.
    if base is None:
        if sel & 4:
            # LDT
            base = state.solver.eval(state.regs.ldt[:32])
            limit = state.solver.eval(state.regs.ldt[32:])
        else:
            # GDT
            base = state.solver.eval(state.regs.gdt[:32])
            limit = state.solver.eval(state.regs.gdt[32:].concrete)

    sel = sel & 0xf8
    if sel + 7 > limit:
        raise Exception('Attempted to index GDT/LDT with segment greater than limit')
    table_addr = (base + sel)
    descriptor = state.solver.eval(
                   state.memory.load(
                     table_addr, 8, disable_actions=True, inspect=False), cast_to=bytes
                 )
    seg_base = ((descriptor[2] | (descriptor[3] << 8) | 
                (descriptor[4] << 16) | (descriptor[7] << 24)))
    return seg_base + offset

def x86step(state, **kwargs):
    if state.history.jump_balance < 0:
        eip_base = dt_lookup(state, state.solver.eval(state.regs.cs), 0)
        state.regs.pc += eip_base
        state.history.jump_balance = 0

    successors = state.project.factory.successors(state, **kwargs)

    for s in successors:
        if s.history.jumpkind == 'Ijk_Ret':
            s.history.jump_balance = state.history.jump_balance - 1
        elif s.history.jumpkind == 'Ijk_Call':
            s.history.jump_balance = state.history.jump_balance + 1
        else:
            s.history.jump_balance = state.history.jump_balance

    return successors

class AngrX86():
    def __init__(self):
        self.info_factory = InstructionInfoFactory()

        def create_enum_dict(module: ModuleType) -> Dict[int, str]:
            return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

        self.reg_map = create_enum_dict(Register)
        self.opac_map = create_enum_dict(OpAccess)

    def used_mem_to_string(self, mem_info):
        sb = "[" + self.reg_map[mem_info.segment] + ":"
        need_plus = mem_info.base != Register.NONE
        if need_plus:
            sb += self.reg_map[mem_info.base]
        if mem_info.index != Register.NONE:
            if need_plus:
                sb += "+"
            need_plus = True
            sb += self.reg_map[mem_info.index]
            if mem_info.scale != 1:
                sb += "*" + str(mem_info.scale)
        if mem_info.displacement != 0 or not need_plus:
            if need_plus:
                sb += "+"
            sb += f"0x{mem_info.displacement:X}"
        sb += ";" + self.opac_map[mem_info.access] + "]"
        return sb

    def get_accessed_seg(self, i, t):
        '''
        @param i is the iced_x86 instruction
        @param t is the the type of access to look for (read or write)
        '''
        for mi in self.info_factory.info(i).used_memory():
            ot = 'write' if 'WRITE' in self.opac_map[mi.access] else 'read'
            if ot == t:
                return self.reg_map[mi.segment].lower()
    
    def x86_translate(self, state, t='read'):
        seg = self.get_accessed_seg(
            [i for i in Decoder(32, state.block().disassembly.insns[0].bytes)][0], t
        )

        # Weird mismatched read to write problem in angr
        if not seg:
            return

        seg = state.solver.eval(getattr(state.regs, seg))

        if t == 'read':
            state.inspect.mem_read_address = dt_lookup(state, seg, 
                state.solver.eval(state.inspect.mem_read_address))
        else:
            state.inspect.mem_write_address = dt_lookup(state, seg, 
                state.solver.eval(state.inspect.mem_write_address))
        

    def x86init(self, state):
        eip_base = dt_lookup(state, state.solver.eval(state.regs.cs), 0)
        state.regs.pc += eip_base
        # If the jump balance is negative, return instructions do not properly 
        # preserve eip offset.
        state.history.jump_balance = 0

        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s: self.x86_translate(s,'write'))
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=lambda s: self.x86_translate(s))
