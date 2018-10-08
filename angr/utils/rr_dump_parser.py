from .parser_util import accept, accept_first, regex_accept_list, accept_all, accept_loop, lstrip

KEY_REGEX = '[0-9a-zA-Z_]+'
STRING_REGEX = "'[^']*'"
NUM_FLOAT_REGEX = '[0-9]+\.[0-9]+'
NUM_HEX_REGEX = '0x[0-9a-fA-F]+'
NUM_DEC_REGEX = '[0-9]+'
IDENT_REGEX = '[A-Za-z_][0-9A-Za-z_]*'
NIL_REGEX = '\(nil\)'


accept_value = accept_first(*regex_accept_list(NIL_REGEX, STRING_REGEX, NUM_FLOAT_REGEX, NUM_HEX_REGEX, NUM_DEC_REGEX, IDENT_REGEX))
accept_key_value = lstrip(accept_all(*regex_accept_list(KEY_REGEX, ':'), accept_value))
def accept_paren_key_value(s):
    val, rest = lstrip(accept_all(accept('\('), accept_key_value, accept('\)')))(s)
    if val is None:
        return val, s
    return val[1], rest # (val[0], val[1], val[2]) == ('(', val, ')')


accept_memory_effects = accept_all(lstrip(accept('{')),
                                   accept_loop(lstrip(accept_key_value)),
                                   lstrip(accept('}')))

accept_event = accept_all(lstrip(accept('{')),
                          accept_loop(accept_first(accept_key_value, accept_paren_key_value)),
                          accept_loop(accept_memory_effects),
                          lstrip(accept('}')))

accept_event_trace = lstrip(accept_loop(accept_event))


def parse_key_value(data, expected_key=None):
    if expected_key is not None and expected_key != data[0]:
        raise ValueError("Expected key {}, got {}!".format(expected_key, data))

    if data[2].startswith('0x'):
        val = int(data[2], base=16)
    elif data[2] == '(nil)':
        val = 0
    elif data[2][0] in '0123456789':
        if '.' in data[2]:
            val = float(data[2])
        else:
            val = int(data[2], base=10)
    elif data[2][0] == '\'':
        assert data[2][-1] == '\''
        val = data[2][1:-1]
    else:
        val = data[2]
    return data[0], val


def pop_key_into_dict(key_val_list, d, expected_key=None):
    data = key_val_list.pop(0)
    key, val = parse_key_value(data, expected_key=expected_key)
    d[key] = val


def parse_key_val_sequence(data, force_unique=True):
    r = {}
    for entry in data:
        key, val = parse_key_value(entry)
        if force_unique and key in r:
            raise ValueError("Key {} is duplicate in {}!".format(key, data))
        r[key] = val
    return r


def parse_event_raw(data):
    assert data[0] == '{' and data[-1] == '}'
    payload_key_vals = data[1]
    payload_mem_mods = data[2]

    r = {}
    r['vals'] = parse_key_val_sequence(payload_key_vals)
    r['mem_mods'] = []
    for mod in payload_mem_mods:
        assert mod[0] == '{' and mod[2] == '}'
        r['mem_mods'].append(parse_key_val_sequence(mod[1]))

    return r


SHARED_KEYS = {'real_time', 'global_time', 'tid', 'ticks', 'event', 'state'}
def parse_event(data):
    p = parse_event_raw(data)
    r = {k: p['vals'][k] for k in p['vals'] if k in SHARED_KEYS} # copy over the shared ones

    ev = p['vals']['event']
    r['info'] = {}
    if ':' not in ev:
        r['event_type'] = ev
    else:
        r['event_type'] = ev[:ev.index(': ')]
        r['info'][r['event_type']] = ev[ev.index(': ')+2:]

    if 'state' in p['vals']:
        r['info']['state'] = p['vals']['state']

    r['info']['regs'] = {}
    if r['event_type'] not in {"EXIT"}:
        # everything that's not shared is a register, always!
        r['info']['regs'] = {k: v for k, v in p['vals'].items() if k not in SHARED_KEYS}

    r['info']['mem'] = []
    for m in p['mem_mods']:
        if m['data'] == 'none':
            assert False, "GO FUCK YOURSELF RR!"
        data_decoded = bytes.fromhex(m['data'])
        assert m['length'] == len(data_decoded)
        new = {'addr': m['addr'], 'tid': m['tid'], 'length': m['length'], 'data': data_decoded}
        r['info']['mem'].append(new)

    return r

def preprocess(s):
    return s.replace('`', '\'').replace(',', '')


class RRDumpParser(object):
    @staticmethod
    def parse_event(event_string):
        s = preprocess(event_string)
        data, rest = accept_event(s=s)
        assert rest.strip() == ''
        return parse_event(data)

    @staticmethod
    def parse_event_trace(trace_string):
        s = preprocess(trace_string)
        data, rest = accept_event_trace(s=s)
        assert rest.strip() == ''
        return [parse_event(e) for e in data]

