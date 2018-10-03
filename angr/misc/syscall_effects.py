class ConcreteSyscallEffects:
    def __init__(self, return_value, memory_effects=None, stub_only=True):
        self.return_value = return_value
        self.memory_effects = { } if memory_effects is None else memory_effects
        self._stub_only = stub_only

    def __call__(self, state, run=None):
        if self._stub_only and not run.is_stub:
            return run._dispatch(state)
        else:
            for addr,data in self.memory_effects.items():
                state.memory.store(addr, data)
            return self.return_value
