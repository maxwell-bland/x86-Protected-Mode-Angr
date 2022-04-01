# x86-protected-mode-angr

x86 protected mode support for angr.

```
pip3 install angr
pip3 install iced_x86
```

### Features left to implement.

- Segment translation currently indexes into the GDT/LDT directly, thus this 
  does not support code that actively modifies the GDT/LDT, pretty uncommon.
- No interrupt support
- No task switching/callgate support

## 

Example use:
```
from angr_x86_protected_support import *

entry_points = {
        'set_two_fields': 0x1080cb9,
        'parse_ops': 0x108ba40,
        'while_loops': 0x1094d80
}
loader = cle.Loader('app.bin',
                    main_opts={'backend': 'blob',
                               'arch': 'i386',
                               'base_addr': 0x1000000,
                               'entry_point': 0x300cb9
                    },
                    rebase_granularity=0x1000,
                    page_size=1,
                    auto_load_libs=False)

f = '00100000_00205fff.bin'
b = cle.backends.Blob(f, open(f, 'rb'), loader=loader,
                      is_main_bin=False, arch='i386', auto_load_libs=False,
                      base_addr=0x100000, pic=True)
loader.dynamic_load(b)

f = '00300120_0031a618.bin'
b = cle.backends.Blob(f, open(f, 'rb'), loader=loader, is_main_bin=False,
                      arch='i386', auto_load_libs=False, base_addr=0x300120, pic=True)
loader.dynamic_load(b)

dt = '00003964_00003d7b.bin'
b = cle.backends.Blob(dt, open(dt, 'rb'), loader=loader, is_main_bin=False, arch='i386',
                      auto_load_libs=False, base_addr=0x3964, pic=True)
loader.dynamic_load(b)

dt = '00003fa4_000040c3.bin'
b = cle.backends.Blob(dt, open(dt, 'rb'), loader=loader, is_main_bin=False, arch='i386',
                      auto_load_libs=False, base_addr=0x3fa4, pic=True)
loader.dynamic_load(b)

p = angr.Project(loader)
state = p.factory.entry_state()
state.regs.cs = 0x00000007
state.regs.eip = 0xb99
state.regs.eax = 0x00104F0C
state.regs.ebx = 0x00104D0C
state.regs.ds = 0x0000000F
state.regs.ecx = 0x000000F8
state.regs.edx = 0x00104E0C
state.regs.edi = 0x00031630
state.regs.flags = 0x00000246
state.regs.esi = 0x00104E0C
state.regs.ebp = 0x51050EAD
state.regs.esp = 0x00104D0C
state.regs.ss = 0x0000000F
state.regs.es = 0x00000037
state.regs.fs = 0x00000047
state.regs.gs = 0x00000047
state.regs.gdt = state.solver.Concat(claripy.BVV(
        0x00003964, 32), claripy.BVV(0x00000417, 32)).zero_extend(16)
state.regs.ldt = state.solver.Concat(claripy.BVV(
    0x00003fa4, 32), claripy.BVV(0x0000011f, 32)).zero_extend(16)

state.memory.store(0x00204e0c,claripy.BVS('buffer',9*8))

AngrX86().x86init(state)

sm = p.factory.simulation_manager(state)

sm.step(successor_func=x86step)
```
