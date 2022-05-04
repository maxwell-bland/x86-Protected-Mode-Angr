import angr
import cle
import claripy
import IPython
import traceback
import archinfo
import warnings
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
FLOW_CONTROL = create_enum_dict(FlowControl)

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

def get_inst_from_addr(state, pc):
    instr_bytes = state.solver.eval(state.memory.load( 
        pc, 0x10, disable_actions=True, inspect=False), cast_to=bytes)
    return [i for i in Decoder(32, instr_bytes)][0]

def get_cur_inst(state):
    '''
    @param pc_val the correct program counter value, either the state's address
    or the instruction pointer register, depending on where this is called from
    '''
    pc = state.solver.eval(state.addr)
    instr_bytes = state.solver.eval( state.memory.load( 
        pc, 0x10, disable_actions=True, inspect=False), cast_to=bytes)
    return [i for i in Decoder(32, instr_bytes)][0]

def get_seg_accessed(i,t):
    '''
    @param i is the iced_x86 instruction
    @param t is the the type of access to look for (read or write)
    '''
    for mi in INFO_FACT.info(i).used_memory():
        ot = 'write' if 'WRITE' in OPAC_MAP[mi.access] else 'read'
        if ot == t:
            return REG_MAP[mi.segment].lower()

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
    
def stack_push(state, val):
    state.regs.esp = state.solver.eval(state.regs.esp) - 4
    stack_addr = dt_lookup(state, state.solver.eval(state.regs.ss), state.solver.eval(state.regs.esp))
    state.memory.store(stack_addr, val, endness=archinfo.Endness.LE)

def int_handler(state):
    user_ss = state.regs.ss.zero_extend(16)
    user_esp = state.regs.esp

    state.regs.esp = state.history.esp0
    state.regs.ss = state.history.ss0

    kernel_stack_addr = dt_lookup(state, state.solver.eval(state.regs.ss), state.solver.eval(state.regs.esp))

    stack_push(state, state.regs.pc)
    stack_push(state, state.regs.cs.zero_extend(16))
    stack_push(state, state.regs.eflags)
    stack_push(state, user_esp)
    stack_push(state, user_ss)

    insn = get_cur_inst(state)
    int_num = insn.immediate16

    base = state.history.idt_base
    limit = state.history.idt_limit
    table_addr = base + 8 * int_num
    descriptor = state.solver.eval(
                   state.memory.load(
                     table_addr, 8, disable_actions=True, inspect=False),
                     cast_to=bytes
                 )
    code_seg_selector =  (descriptor[2]) | (descriptor[3] << 8)
    state.regs.cs = code_seg_selector
    offset = dt_lookup(state, code_seg_selector, 0)
    seg_base = ((descriptor[0] | (descriptor[1] << 8) | 
                (descriptor[6] << 16) | (descriptor[7] << 24)))
    state.regs.pc = seg_base + offset

    return seg_base+offset

def iretd_handler(state):
    user_ss = state.stack_pop()
    user_ss = user_ss.get_bytes(2,2)
    user_esp = state.stack_pop()
    user_eflags = state.stack_pop()
    user_cs = state.stack_pop()
    user_cs = user_cs.get_bytes(2,2)
    user_pc = state.stack_pop()

    state.regs.ss = user_ss
    state.regs.esp = user_esp
    state.regs.eflags = user_eflags
    state.regs.cs = user_cs
    state.regs.pc = state.solver.eval(user_pc)+1

def mem_translate(state, t='read'):
    '''
    Method for translating segment accesses in instructions: we dothis
    rather than get_mem_info since it works despite angr instruction issues
    '''
    i = get_cur_inst(state)
    seg = get_seg_accessed(i, t)

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

# Instruction handlers

def memory_translate(state, seg='ds', base_reg=None, scale=1, displacement=0, index_reg=None, **kwargs):
    addr = 0
    if base_reg:
        addr = state.solver.eval(getattr(state.regs,base_reg))
    if index_reg:
        addr += state.solver.eval(getattr(state.regs,index_reg)) * scale
    if displacement:
        addr += displacement
    return dt_lookup(state, state.solver.eval(getattr(state.regs, seg)), addr)

def les_fix(state, inst_len, write_reg='eax', **kwargs):
    mem_val = state.memory.load(
        memory_translate(state, **kwargs),
        6, 
        disable_actions=True, 
        inspect=False
    ).reversed

    setattr(state.regs,write_reg,mem_val[31:])
    state.regs.es = mem_val[:32]
    state.regs.pc += inst_len

def handle_indirect(state):
    i = get_cur_inst(state)
    if i.is_call_near_indirect or i.is_jmp_near_indirect:
        state.inspect.mem_read_expr += dt_lookup(state, state.solver.eval(state.regs.cs), 0)
    if i.is_call_far or i.is_jmp_far:
        info = INFO_FACT.info(i)
        info.used_registers()

# Angr breakpoint handlers and initialization
# Custom simulation steppers

def x86_instruction_fixes(state):
    # The x86 instruction set guarantees instructions are no more than 15 bytes
    # we use state.addr here since this is part of the step function
    i = get_cur_inst(state)
    print("HIT x86 insn FIX!",MNEMONIC_MAP.get(i.mnemonic))
    if MNEMONIC_MAP.get(i.mnemonic) == 'LES':
        info = INFO_FACT.info(i)
        mi = info.used_memory()[0]
        mi = get_mem_info(mi)
        mi['write_reg'] = REG_MAP[info.used_registers()[-2].register].lower()
        les_fix(state, i.len, **mi)
    elif MNEMONIC_MAP.get(i.mnemonic) == 'RETF':
        ret_addr = state.stack_pop()
        ret_addr = dt_lookup(state, state.solver.eval(getattr(state.regs, seg)), ret_addr)
        state.regs.pc = ret_addr 
    elif MNEMONIC_MAP.get(i.mnemonic) == 'CALL':
        offset = i.immediate32
        base_seg = i.immediate64 >> 32
        state.stack_push(state.regs.pc)
        state.regs.pc = dt_lookup(state, seg_val, offset)
        IPython.embed()
    elif MNEMONIC_MAP.get(i.mnemonic) == 'IRETD':
        iretd_handler(state)
        print('iret handled, pc:', state.regs.pc)

def check_fixup_iretd(state):
    curblock = state.block()
    if not curblock or not curblock.disassembly.insns:
        return
    block_fi = curblock.disassembly.insns[-1]
    if block_fi.mnemonic == 'iretd':
        state.project.hook(
            block_fi.address, hook=x86_instruction_fixes)

def x86step(state, **kwargs):
    check_fixup_iretd(state)

    try:
        successors = state.project.factory.successors(state, **kwargs)
    except:
        if not state.project.is_hooked(state.addr):
            state.project.hook(state.addr, hook=x86_instruction_fixes)
            return x86step(state)

    for s in successors:
        if s.history.jumpkind == 'Ijk_NoDecode' and not s.project.is_hooked(s.history.jump_target):
            state.project.hook(s.solver.eval(s.history.jump_target), hook=x86_instruction_fixes)
            return x86step(state)

    for s in successors:

        s.history.idt_base = state.history.idt_base
        s.history.idt_limit = state.history.idt_limit
        s.history.ss0 = state.history.ss0
        s.history.esp0 = state.history.esp0

        insn = get_cur_inst(s)
        # TODO seperate out logic for recursively resolving interrupts+calls into
        # another function
        if FLOW_CONTROL.get(insn.flow_control) == 'INTERRUPT':
            assert(len(list(successors)) == 1)
            landing = int_handler(s)
            i = get_inst_from_addr(s,landing)
            if MNEMONIC_MAP.get(i.mnemonic) == 'CALL':
                print("HIT CALLF")
                offset = i.immediate32
                seg_val = i.immediate64 >> 32
                state.stack_push(state.regs.pc)
                state.regs.pc = dt_lookup(state, seg_val, offset)
                print(state.regs.pc)
                return x86step(state)
        # NOTE: assumes that we never have a RETF with a negative jump balance
        elif MNEMONIC_MAP.get(insn.mnemonic) == 'RETF':
            assert(len(list(successors)) == 1)
            ret_addr = state.stack_pop()
            state.regs.pc = ret_addr
            print('return to: ', ret_addr)
            return x86step(state)

        if s.history.jumpkind == 'Ijk_Ret':
            s.history.jump_balance = state.history.jump_balance - 1
        elif s.history.jumpkind == 'Ijk_Call':
            s.history.jump_balance = state.history.jump_balance + 1
        else:
            s.history.jump_balance = state.history.jump_balance

        if s.history.jump_balance < 0:
            eip_base = dt_lookup(s, s.solver.eval(s.regs.cs), 0)
            s.regs.pc += eip_base
            s.history.jump_balance = 0

    return successors

def x86init(state, idt_base=None, idt_limit=None, ss0=None, esp0=None):
    eip_base = dt_lookup(state, state.solver.eval(state.regs.cs), 0)
    state.regs.pc += eip_base
    # If the jump balance is negative, return instructions do not properly 
    # preserve eip offset.
    state.history.jump_balance = 0
    state.history.idt_base = idt_base
    state.history.idt_limit = idt_limit
    state.history.ss0 = ss0
    state.history.esp0 = esp0

    if idt_base is None or idt_limit is None or ss0 is None or esp0 is None:
        warnings.warn('Interrupt support disabled.')

    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=lambda s: mem_translate(s,'write'))
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_translate)
