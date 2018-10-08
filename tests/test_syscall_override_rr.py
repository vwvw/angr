import angr

import logging
import subprocess
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

target_addrs = {
    'i386': [ 0x080485C9 ],
    'x86_64': [ 0x4006ed ],
}

avoid_addrs = {
    'i386': [ 0x080485DD,0x08048564 ],
    'x86_64': [ 0x4006aa,0x4006fd ],
}

def extract_syscall_effects(trace, syscall_filter=None):
    for event in trace:
        if not event['event'].startswith('SYSCALL'):
            continue

        if event['info']['state'] != 'EXITING_SYSCALL':
            continue

        if syscall_filter is not None and event['info']['SYSCALL'] not in syscall_filter:
            yield None
            continue

        ret = event['info']['regs']['rax']
        mem_effects = {m['addr']: m['data'] for m in event['info']['mem']}
        yield angr.misc.ConcreteSyscallEffects(return_value=ret, memory_effects = mem_effects, stub_only=False)


def test_rr_fauxware_correct(arch="x86_64"):
    binary_path = os.path.join(test_location, arch, "fauxware")
    p = angr.Project(binary_path, use_sim_procedures=False)
    s = p.factory.full_init_state()

    with open('./fauxware_correct.rr') as f:
        trace_string = f.read()
        trace = angr.utils.RRDumpParser.parse_event_trace(trace_string)

    concrete_effects = [
        eff for eff in extract_syscall_effects(trace, syscall_filter={'read'})
    ]
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

if __name__ == "__main__":
    test_rr_fauxware_correct('x86_64')
