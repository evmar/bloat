#!/usr/bin/python

import fileinput
import operator
import optparse
import os
import pprint
import re
import subprocess
import sys
import json

def format_bytes(bytes):
    """Pretty-print a number of bytes."""
    if bytes > 1e6:
        bytes = bytes / 1.0e6
        return '%.1fm' % bytes
    if bytes > 1e3:
        bytes = bytes / 1.0e3
        return '%.1fk' % bytes
    return str(bytes)


def symbol_type_to_human(type):
    """Convert a symbol type as printed by nm into a human-readable name."""
    return {
        'b': 'bss',
        'd': 'data',
        'r': 'read-only data',
        't': 'code',
        'w': 'weak symbol',
        'v': 'weak symbol'
        }[type]


def parse_nm(input):
    """Parse nm output.

    Argument: an iterable over lines of nm output.

    Yields: (symbol name, symbol type, symbol size, source file path).
    Path may be None if nm couldn't figure out the source file.
    """

    # Match lines with size + symbol + optional filename.
    sym_re = re.compile(r'^[0-9a-f]+ ([0-9a-f]+) (.) ([^\t]+)(?:\t(.*):\d+)?$')

    # Match lines with addr but no size.
    addr_re = re.compile(r'^[0-9a-f]+ (.) ([^\t]+)(?:\t.*)?$')
    # Match lines that don't have an address at all -- typically external symbols.
    noaddr_re = re.compile(r'^ + (.) (.*)$')

    for line in input:
        line = line.rstrip()
        match = sym_re.match(line)
        if match:
            size, type, sym = match.groups()[0:3]
            size = int(size, 16)
            type = type.lower()
            if type == 'v':
                type = 'w'  # just call them all weak
            if type == 'b':
                continue  # skip all BSS for now
            path = match.group(4)
            yield sym, type, size, path
            continue
        match = addr_re.match(line)
        if match:
            type, sym = match.groups()[0:2]
            # No size == we don't care.
            continue
        match = noaddr_re.match(line)
        if match:
            type, sym = match.groups()
            if type in ('U', 'w'):
                # external or weak symbol
                continue

        print >>sys.stderr, 'unparsed:', repr(line)


def parse_cpp_name(name):
    # Turn prefixes into suffixes so namespacing works.
    prefixes = [
        ['bool ',                         ''],
        ['construction vtable for ',      ' [construction vtable]'],
        ['global constructors keyed to ', ' [global constructors]'],
        ['int ',                          ''],
        ['non-virtual thunk to ',         ' [non-virtual thunk]'],
        ['typeinfo for ',                 ' [typeinfo]'],
        ['typeinfo name for ',            ' [typeinfo name]'],
        ['virtual thunk to ',             ' [virtual thunk]'],
        ['void ',                         ''],
        ['vtable for ',                   ' [vtable]'],
    ]
    for prefix, replacement in prefixes:
        if name.startswith(prefix):
            name = name[len(prefix):] + replacement
    # Simplify parenthesis parsing.
    replacements = [
        ['(anonymous namespace)', '[anonymous namespace]'],
    ]
    for value, replacement in replacements:
        name = name.replace(value, replacement)

    def parse_one(val):
        """Returns (leftmost-part, remaining)."""
        if (val.startswith('operator') and
            not (val[8].isalnum() or val[8] == '_')):
            # Operator overload function, terminate.
            return (val, '')
        co = val.find('::')
        lt = val.find('<')
        pa = val.find('(')
        co = len(val) if co == -1 else co
        lt = len(val) if lt == -1 else lt
        pa = len(val) if pa == -1 else pa
        if co < lt and co < pa:
            # Namespace or type name.
            return (val[:co], val[co+2:])
        if lt < pa:
            # Template. Make sure we capture nested templates too.
            open_tmpl = 1
            gt = lt
            while val[gt] != '>' or open_tmpl != 0:
                gt = gt + 1
                if val[gt] == '<':
                    open_tmpl = open_tmpl + 1
                if val[gt] == '>':
                    open_tmpl = open_tmpl - 1
            ret = val[gt+1:]
            if ret.startswith('::'):
                ret = ret[2:]
            if ret.startswith('('):
                # Template function, terminate.
                return (val, '')
            return (val[:gt+1], ret)
        # Terminate with any function name, identifier, or unmangled name.
        return (val, '')

    parts = []
    while len(name) > 0:
        (part, name) = parse_one(name)
        assert len(part) > 0
        parts.append(part)
    return parts


def treeify_syms(symbols, strip_prefix=None, cppfilt=None):
    dirs = {}
    for sym, type, size, path in symbols:
        if path:
            path = os.path.normpath(path)
            if strip_prefix and path.startswith(strip_prefix):
                path = path[len(strip_prefix):]
            elif path.startswith('/'):
                path = path[1:]
            path = ['[path]'] + path.split('/')

        parts = parse_cpp_name(sym)
        if len(parts) == 1:
          if path:
            # No namespaces, group with path.
            parts = path + parts
          else:
            new_prefix = ['[ungrouped]']
            regroups = [
                ['.L.str',                 '[str]'],
                ['.L__PRETTY_FUNCTION__.', '[__PRETTY_FUNCTION__]'],
                ['.L__func__.',            '[__func__]'],
                ['.Lswitch.table',         '[switch table]'],
            ]
            for prefix, group in regroups:
                if parts[0].startswith(prefix):
                    parts[0] = parts[0][len(prefix):]
                    if cppfilt and parts[0].startswith('_Z'):
                        # Demangle names when possible.
                        # Mangled names all start with _Z.
                        parts[0] = subprocess.check_output(
                            [cppfilt, parts[0]]).strip()
                    new_prefix += [group]
                    break
            parts = new_prefix + parts

        key = parts.pop()
        tree = dirs
        try:
            depth = 0
            for part in parts:
                depth = depth + 1
                assert part != '', path
                if part not in tree:
                    tree[part] = {'$bloat_symbols':{}}
                if type not in tree[part]['$bloat_symbols']:
                    tree[part]['$bloat_symbols'][type] = 0
                tree[part]['$bloat_symbols'][type] += 1
                tree = tree[part]
            old_size, old_symbols = tree.get(key, (0, {}))
            if type not in old_symbols:
                old_symbols[type] = 0
            old_symbols[type] += 1
            tree[key] = (old_size + size, old_symbols)
        except:
            print >>sys.stderr, 'sym `%s`\tparts `%s`\tkey `%s`' % (sym, parts, key)
            raise
    return dirs


def jsonify_tree(tree, name):
    children = []
    total = 0
    files = 0

    for key, val in tree.iteritems():
        if key == '$bloat_symbols':
            continue
        if isinstance(val, dict):
            subtree = jsonify_tree(val, key)
            total += subtree['data']['$area']
            children.append(subtree)
        else:
            (size, symbols) = val
            total += size
            assert len(symbols) == 1, symbols.values()[0] == 1
            symbol = symbol_type_to_human(symbols.keys()[0])
            children.append({
                    'name': key + ' ' + format_bytes(size),
                    'data': {
                        '$area': size,
                        '$symbol': symbol,
                    }
            })

    children.sort(key=lambda child: -child['data']['$area'])
    dominant_symbol = ''
    if '$bloat_symbols' in tree:
        dominant_symbol = symbol_type_to_human(
            max(tree['$bloat_symbols'].iteritems(),
                key=operator.itemgetter(1))[0])
    return {
        'name': name + ' ' + format_bytes(total),
        'data': {
            '$area': total,
            '$dominant_symbol': dominant_symbol,
            },
        'children': children,
        }


def dump_nm(nmfile, strip_prefix, cppfilt):
    dirs = treeify_syms(parse_nm(nmfile), strip_prefix, cppfilt)
    print ('var kTree = ' +
           json.dumps(jsonify_tree(dirs, '[everything]'), indent=2))


def parse_objdump(input):
    """Parse objdump -h output."""
    sec_re = re.compile('^\d+ (\S+) +([0-9a-z]+)')
    sections = []
    debug_sections = []

    for line in input:
        line = line.strip()
        match = sec_re.match(line)
        if match:
            name, size = match.groups()
            if name.startswith('.'):
                name = name[1:]
            if name.startswith('debug_'):
                name = name[len('debug_'):]
                debug_sections.append((name, int(size, 16)))
            else:
                sections.append((name, int(size, 16)))
            continue
    return sections, debug_sections


def jsonify_sections(name, sections):
    children = []
    total = 0
    for section, size in sections:
        children.append({
                'name': section + ' ' + format_bytes(size),
                'data': { '$area': size }
                })
        total += size

    children.sort(key=lambda child: -child['data']['$area'])

    return {
        'name': name + ' ' + format_bytes(total),
        'data': { '$area': total },
        'children': children
        }


def dump_sections(objdump):
    sections, debug_sections = parse_objdump(objdump)
    sections = jsonify_sections('sections', sections)
    debug_sections = jsonify_sections('debug', debug_sections)
    size = sections['data']['$area'] + debug_sections['data']['$area']
    print 'var kTree = ' + json.dumps({
            'name': 'top ' + format_bytes(size),
            'data': { '$area': size },
            'children': [ debug_sections, sections ]})


usage="""%prog [options] MODE

Modes are:
  syms: output symbols json suitable for a treemap
  dump: print symbols sorted by size (pipe to head for best output)
  sections: output binary sections json suitable for a treemap

nm output passed to --nm-output should from running a command
like the following (note, can take a long time -- 30 minutes):
  nm -C -S -l /path/to/binary > nm.out

objdump output passed to --objdump-output should be from a command
like:
  objdump -h /path/to/binary > objdump.out"""
parser = optparse.OptionParser(usage=usage)
parser.add_option('--nm-output', action='store', dest='nmpath',
                  metavar='PATH', default='nm.out',
                  help='path to nm output [default=nm.out]')
parser.add_option('--objdump-output', action='store', dest='objdumppath',
                  metavar='PATH', default='objdump.out',
                  help='path to objdump output [default=objdump.out]')
parser.add_option('--strip-prefix', metavar='PATH', action='store',
                  help='strip PATH prefix from paths; e.g. /path/to/src/root')
parser.add_option('--filter', action='store',
                  help='include only symbols/files matching FILTER')
parser.add_option('--c++filt', action='store', metavar='PATH', dest='cppfilt',
                  default='c++filt', help="Path to c++filt, used to demangle "
                  "symbols that weren't handled by nm. Set to an invalid path "
                  "to disable.")
opts, args = parser.parse_args()

if len(args) != 1:
    parser.print_usage()
    sys.exit(1)

mode = args[0]
if mode == 'syms':
    nmfile = open(opts.nmpath, 'r')
    try:
        res = subprocess.check_output([opts.cppfilt, 'main'])
        if res.strip() != 'main':
            print >>sys.stderr, ("%s failed demangling, "
                                 "output won't be demangled." % opt.cppfilt)
            opts.cppfilt = None
    except:
        print >>sys.stderr, ("Could not find c++filt at %s, "
                             "output won't be demangled." % opt.cppfilt)
        opts.cppfilt = None
    dump_nm(nmfile, strip_prefix=opts.strip_prefix, cppfilt=opts.cppfilt)
elif mode == 'sections':
    objdumpfile = open(opts.objdumppath, 'r')
    dump_sections(objdumpfile)
elif mode == 'dump':
    nmfile = open(opts.nmpath, 'r')
    syms = list(parse_nm(nmfile))
    # a list of (sym, type, size, path); sort by size.
    syms.sort(key=lambda x: -x[2])
    total = 0
    for sym, type, size, path in syms:
        if type in ('b', 'w'):
            continue  # skip bss and weak symbols
        if path is None:
            path = ''
        if opts.filter and not (opts.filter in sym or opts.filter in path):
            continue
        print '%6s %s (%s) %s' % (format_bytes(size), sym,
                                  symbol_type_to_human(type), path)
        total += size
    print '%6s %s' % (format_bytes(total), 'total'),
else:
    print 'unknown mode'
    parser.print_usage()
