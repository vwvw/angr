import angr

import logging
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

target_addrs = {
    'i386': [ 0x080485C9 ],
    'x86_64': [ 0x4006ed ],
    'ppc': [ 0x1000060C ],
    'armel': [ 0x85F0 ],
    'mips': [ 0x4009FC ]
}

avoid_addrs = {
    'i386': [ 0x080485DD,0x08048564 ],
    'x86_64': [ 0x4006aa,0x4006fd ],
    'ppc': [ 0x10000644,0x1000059C ],
    'armel': [ 0x86F8,0x857C ],
    'mips': [ 0x400A10,0x400774 ]
}

def run_fauxware_override(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"), use_sim_procedures=False)
    s = p.factory.full_init_state()

    def overwrite_str(state):
        state.posix.get_fd(1).write_data(b"HAHA\0")

    #s.posix.queued_syscall_returns = [ ]
    s.posix.queued_syscall_returns.append(None) # let the fstat run
    s.posix.queued_syscall_returns.append(overwrite_str) # prompt for username
    s.posix.queued_syscall_returns.append(0) # username read
    s.posix.queued_syscall_returns.append(0) # newline read
    #s.posix.queued_syscall_returns.append(0) # prompt for password -- why isn't this called?
    s.posix.queued_syscall_returns.append(None) # password input
    s.posix.queued_syscall_returns.append(0) # password \n input

    results = p.factory.simulation_manager(thing=s).explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    assert results.found[0].posix.dumps(0) == b'SOSNEAKY'
    assert results.found[0].posix.dumps(1) == b"HAHA\0"

def test_concrete_syscall_effects(arch="x86_64"):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"), use_sim_procedures=False)
    s = p.factory.full_init_state()

    concrete_effects = [
        None, # fstat? why the fuck?
        None, #mmap
        angr.misc.ConcreteSyscallEffects(return_value=8, memory_effects={ 0x7fffffffffefeb0: b"asdfasdf" }, stub_only=False),
        None,
        angr.misc.ConcreteSyscallEffects(return_value=8, memory_effects={ 0x7fffffffffefea0: b"SOSNEAKY" }, stub_only=False),
        #lambda *args, **kwargs: ipdb.set_trace(), #read
        None,
    ]
    s.posix.queued_syscall_returns = concrete_effects

    results = p.factory.simulation_manager(thing=s).explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    assert len(results.found)
    assert len(results.found[0].posix.dumps(0)) == 2

    s = p.factory.full_init_state()
    concrete_effects = [
        None, # fstat? why the fuck?
        None, #mmap
        angr.misc.ConcreteSyscallEffects(return_value=8, memory_effects={ 0x7fffffffffefeb0: b"asdfasdf" }),
        None,
        angr.misc.ConcreteSyscallEffects(return_value=8, memory_effects={ 0x7fffffffffefea0: b"SOSNEAKY" }),
        #lambda *args, **kwargs: ipdb.set_trace(), #read
        None,
    ]
    s.posix.queued_syscall_returns = concrete_effects
    results = p.factory.simulation_manager(thing=s).explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    assert len(results.found)
    assert results.found[0].posix.dumps(0) == b'\0\0\0\0\0\0\0\0\0SOSNEAKY\0'

def test_fauxware_override():
    #for arch in target_addrs:
    #   yield run_fauxware_override, arch
    yield run_fauxware_override, 'x86_64'

if __name__ == "__main__":
    run_fauxware_override('x86_64')
    #for r,a in test_fauxware_override():
    #   r(a)
    test_concrete_syscall_effects()
