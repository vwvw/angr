import functools
import re


def accept(regex):
    def _accept(regex, s):
        match = re.match(regex, s)
        if not match:
            return None, s
        end = match.end()
        return s[:end], s[end:]
    return functools.partial(_accept, regex)

def expect(accepter):
    def _expect(accept, s):
        val, rest = accept(s)
        if val is None:
            raise ValueError("Expected {}, got {}!".format(accepter, s))

    return functools.partial(_expect, accepter)

def accept_first(*args):
    def _accept_first(*args, s):
        for f in args:
            val, rest = f(s)
            if val is not None:
                return val, rest
        return None, s

    return functools.partial(_accept_first, *args)

def accept_all(*args):
    def _accept_all(*args, s=None):
        _s = s
        vals = []
        for f in args:
            val, s = f(s=s)
            if val is None:
                return None, _s
            vals.append(val)

        return vals, s

    return functools.partial(_accept_all, *args)

def accept_loop(f):
    def _accept(f, s):
        vals = []
        while True:
            val, s = f(s=s)
            if val is None:
                return vals, s
            vals.append(val)

    return functools.partial(_accept, f)


def regex_accept_list(*regexes):
    return [accept(regex) for regex in regexes]


def accept_first_regex(*args):
    return accept_first(regex_accept_list(*args))


def lstrip(f):
    def _lstrip(f, s):
        val, rest = accept_all(accept('\s*'), f)(s=s)
        if val is None:
            return val, rest
        return val[1], rest # [0] is the potential whitespace, [1] is our result
    return functools.partial(_lstrip, f)