import angr
import cle
import claripy
import IPython
import traceback
from iced_x86 import *
from types import ModuleType
from typing import Dict, Sequence

# iced_x86 resolvers

def create_enum_dict(module: ModuleType) -> Dict[int, str]:
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

MNEMONIC_MAP = create_enum_dict(Mnemonic)
REG_MAP = create_enum_dict(Register)
OPAC_MAP = create_enum_dict(OpAccess)
INFO_FACT = InstructionInfoFactory()

def get_mem_info(mem_info):
    seg = REG_MAP[mem_info.segment].lower()
    base_reg = None
    scale = 1
    displacement = 0
    index_reg = None
    if mem_info.base != Register.NONE:
        base_reg = REG_MAP[mem_info.base].lower()
    if mem_info.index != Register.NONE:
        index_reg = REG_MAP[mem_info.index].lower()
        scale = mem_info.scale
    if mem_info.displacement:
        displacement = mem_info.displacement
    access_type = OPAC_MAP[mem_info.access]
    return {'seg': seg, 'base_reg': base_reg, 'scale': scale,
            'displacement': displacement, 'index_reg': index_reg,
            'access_type': access_type}

# GDT and LDT lookups

def dt_lookup(state, sel, offset, base=None):
    # Protected mode.
    if base is None:
        if sel & 4:
            # LDT
            base = state.solver.eval(state.regs.ldt[:32])
            limit = state.solver.eval(state.regs.ldt[31:])
        else:
            # GDT
            base = state.solver.eval(state.regs.gdt[:32])
            limit = state.solver.eval(state.regs.gdt[31:])

    sel = sel & 0xf8
    if sel + 7 > limit:
        raise Exception(f'Attempted to index GDT/LDT with segment {sel} greater than limit {limit}')
    table_addr = (base + sel)
    descriptor = state.solver.eval(
                   state.memory.load(
                     table_addr, 8, disable_actions=True, inspect=False), cast_to=bytes
                 )
    seg_base = ((descriptor[2] | (descriptor[3] << 8) | 
                (descriptor[4] << 16) | (descriptor[7] << 24)))
    return seg_base + offset

# Instruction handlers

def les_fix(state, inst_len, write_reg='eax', seg='ds', base_reg=None, scale=1, displacement=0, index_reg=None, **kwargs):
    addr = 0
    if base_reg:
        addr = state.solver.eval(getattr(state.regs,base_reg))
    if index_reg:
        addr += state.solver.eval(getattr(state.regs,base_reg)) * scale
    if displacement:
        addr += displacement

    mem_val = state.memory.load(
        dt_lookup(state, state.solver.eval(getattr(state.regs, seg)), addr), 
        6, 
        disable_actions=True, 
        inspect=False
    ).reversed

    setattr(state.regs,write_reg,mem_val[31:])
    state.regs.es = mem_val[:32]
    state.regs.pc += inst_len

def x86_instruction_fixes(state):
    i = [i for i in Decoder(
        32, state.solver.eval(
            state.memory.load(
                state.addr, 
                20, 
                disable_actions=True, 
                inspect=False
            ), cast_to=bytes))][0]
    if MNEMONIC_MAP.get(i.mnemonic) == 'LES':
        info = INFO_FACT.info(i)
        mi = info.used_memory()[0]
        mi = get_mem_info(mi)
        mi['write_reg'] = REG_MAP[info.used_registers()[-2].register].lower()
        les_fix(state, i.len, **mi)

# Custom simulation steppers

def x86step(state, **kwargs):
    if state.history.jump_balance < 0:
        eip_base = dt_lookup(state, state.solver.eval(state.regs.cs), 0)
        state.regs.pc += eip_base
        state.history.jump_balance = 0

    successors = state.project.factory.successors(state, **kwargs)

    for s in successors:
        if s.history.jumpkind == 'Ijk_NoDecode' and not s.project.is_hooked(s.history.jump_target):
            state.project.hook(s.solver.eval(s.history.jump_target), hook=x86_instruction_fixes)
            return x86step(state)

    for s in successors:
        if s.history.jumpkind == 'Ijk_Ret':
            s.history.jump_balance = state.history.jump_balance - 1
        elif s.history.jumpkind == 'Ijk_Call':
            s.history.jump_balance = state.history.jump_balance + 1
        else:
            s.history.jump_balance = state.history.jump_balance

    return successors

# Angr breakpoint handlers and initialization

class AngrX86():
    def __init__(self):
        pass

    def get_accessed_seg(self, i, t):
        '''
        @param i is the iced_x86 instruction
        @param t is the the type of access to look for (read or write)
        '''
        for mi in INFO_FACT.info(i).used_memory():
            ot = 'write' if 'WRITE' in OPAC_MAP[mi.access] else 'read'
            if ot == t:
                return REG_MAP[mi.segment].lower()
    
    def x86_translate(self, state, t='read'):
        seg = self.get_accessed_seg(
            [i for i in Decoder(32, state.block().disassembly.insns[0].bytes)][0], t
        )

        # Weird mismatched read to write problem in angr
        if not seg:
            return

        seg_val = state.solver.eval(getattr(state.regs, seg))

        try:
            if t == 'read':
                state.inspect.mem_read_address += dt_lookup(state, seg_val, 0)
            else:
                state.inspect.mem_write_address += dt_lookup(state, seg_val, 0)
        except Exception as e:
            print(traceback.format_exc())
            IPython.embed()
        

    def x86init(self, state):
        eip_base = dt_lookup(state, state.solver.eval(state.regs.cs), 0)
        state.regs.pc += eip_base
        # If the jump balance is negative, return instructions do not properly 
        # preserve eip offset.
        state.history.jump_balance = 0

        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s: self.x86_translate(s,'write'))
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=lambda s: self.x86_translate(s))
