import os
import logging
import nose
import angr

l = logging.getLogger("angr.tests")
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

insn_texts = {
    'i386': b"add eax, 15",
    'x86_64': b"add rax, 15",
    'ppc': b"addi %r1, %r1, 15",
    'armel': b"add r1, r1, 15",
    'mips': b"addi $1, $1, 15"
}

def run_keystone(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))
    addr = p.loader.main_object.get_symbol('authenticate').rebased_addr

    sm = p.factory.simulation_manager()
    if arch in ['i386', 'x86_64']:
        sm.one_active.regs.eax = 3
    else:
        sm.one_active.regs.r1 = 3

    block = p.factory.block(addr, insn_text=insn_texts[arch]).vex

    nose.tools.assert_equal(block.instructions, 1)

    sm.step(addr=addr, insn_text=insn_texts[arch])

    if arch in ['i386', 'x86_64']:
        nose.tools.assert_equal(sm.one_active.solver.eval(sm.one_active.regs.eax), 0x12)
    else:
        nose.tools.assert_equal(sm.one_active.solver.eval(sm.one_active.regs.r1), 0x12)

if __name__ == "__main__":
    for arch_name in insn_texts:
        run_keystone(arch_name)