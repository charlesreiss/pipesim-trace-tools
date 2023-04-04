import csv
import logging
import re
import subprocess

logger = logging.getLogger(__name__)

FIELDS = [
    'orig_pc',
    'orig_pc_part',
    'orig_instruction',
    'is_conditional_branch',
    'is_constant_jump',
    'is_computed_jump',
    'srcA',
    'srcB',
    'dst',
    'is_memory_read',
    'is_memory_write',
    'mem_addr',
    'branch_taken',
]

def simplify_mnemonic(mnemonic):
    if mnemonic.startswith('c.'):
        mnemonic = mnemonic[2:]
    if mnemonic.endswith('spn'):
        mnemonic = mnemonic[:-3]
    if mnemonic.endswith('sp'):
        mnemonic = mnemonic[:-2]
    if mnemonic.endswith('pc'):
        mnemonic = mnemonic[:-2]
    if mnemonic.endswith('.w'):
        mnemonic = mnemonic[:-2]
    if mnemonic.endswith('.d'):
        mnemonic = mnemonic[:-2]
    if mnemonic.endswith('16'):
        mnemonic = mnemonic[:-2]
    if mnemonic.endswith('4'):
        mnemonic = mnemonic[:-1]
    return mnemonic

branches = set([
    'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu',
    'beqz', 'bnez', 'bltz', 'bgez',
    'bgt', 'ble', 'bgtu', 'bleu',
])

loads = set([
    'lb', 'lh', 'lw', 'lbu', 'lhu', 'lwu', 'ld', 'flw', 'fld', 'flq', 'lr',
])

stores = set([
    'sb', 'sh', 'sw', 'sd', 'fsw', 'fsd', 'fsq', 'sc',
])

rmw = set([
    'amoadd', 'amoand', 'amoor', 'amoswap', 'amoxor', 'amomax', 'amomin', 'amomaxu', 'amominu',
])

def is_branch(mnemonic):
    return mnemonic in branches

def decode_instruction_raw(raw):
    parts = raw.split()
    mnemonic = simplify_mnemonic(parts[0])
    operands = []
    for part in parts[1:]:
        if part.endswith(','):
            part = part[:-1]
        if '(' in part:
            offset, rest = part.split('(', 1)
            rest = rest[:-1]
            operands.append(rest)
        elif re.match(r'[+-]?[0-9]+|0x[0-9a-f]+', part) != None:
            continue
        elif part == '+' or part == '-':
            continue
        else:
            operands.append(part)
    return {
        'original': raw,
        'mnemonic': mnemonic,
        'operands': operands,
    }

# Chapter 25, RISC V unpriviliged specification
register_map = {
    'ra': 1,
    'sp': 2,
    'gp': 3,
    'tp': 4,
    't0': 5,
    't1': 6,
    't2': 7,
    's0': 8,
    'fp': 8,
    's1': 9,
    'a0': 10,
    'a1': 11,
    'a2': 12,
    'a3': 13,
    'a4': 14,
    'a5': 15,
    'a6': 16,
    'a7': 17,
    's2': 18,
    's3': 19,
    's4': 20,
    's5': 21,
    's6': 22,
    's7': 23,
    's8': 24,
    's9': 25,
    's10': 26,
    's11': 27,
    't3': 28,
    't4': 29,
    't5': 30,
    't6': 31,
    'ft0': 32 + 0,
    'ft1': 32 + 1,
    'ft2': 32 + 2,
    'ft3': 32 + 3,
    'ft4': 32 + 4,
    'ft5': 32 + 5,
    'ft6': 32 + 6,
    'ft7': 32 + 7,
    'fs0': 32 + 8,
    'fs1': 32 + 9,
    'fa0': 32 + 10 + 0,
    'fa1': 32 + 10 + 1,
    'fa2': 32 + 10 + 2,
    'fa3': 32 + 10 + 3,
    'fa4': 32 + 10 + 4,
    'fa5': 32 + 10 + 5,
    'fa6': 32 + 10 + 6,
    'fa7': 32 + 10 + 7,
    'fs2': 32 + 16 + 2,
    'fs3': 32 + 16 + 3,
    'fs4': 32 + 16 + 4,
    'fs5': 32 + 16 + 5,
    'fs6': 32 + 16 + 6,
    'fs7': 32 + 16 + 7,
    'fs8': 32 + 16 + 8,
    'fs9': 32 + 16 + 9,
    'fs10': 32 + 16 + 10,
    'fs11': 32 + 16 + 11,
    'ft8': 32 + 28,
    'ft9': 32 + 28 + 1,
    'ft10': 32 + 28 + 2,
    'ft11': 32 + 28 + 3,
}

def number_register(name):
    global register_map
    if name == 'zero' or name == 'x0':
        return None
    elif name == 'pc':
        return None
    elif name.startswith('x'):
        return int(name[1:])
    elif name.startswith('f') and name[1] != 't' and name[1] != 'a' and name[1] != 's':
        return int(name[1:]) + 32
    elif name in register_map:
        return register_map[name]
    else:
        raise Exception('unknown register {}'.format(name))

def decode_instruction(raw):
    base = decode_instruction_raw(raw)
    base['memory_read'] = base['memory_write'] = base['is_conditional_branch'] = False
    base['is_constant_jump'] = False
    base['is_computed_jump'] = False
    base['destination'] = None
    base['sources'] = []
    if base['mnemonic'] == 'ret':
        base['sources'] = [number_register('ra')]
        base['is_computed_jump'] = True
    elif base['mnemonic'] == 'csrr':
        base['destination'] = number_register(base['operands'][0])
    elif base['mnemonic'] == 'csrw':
        base['sources'] = [number_register(base['operands'][1])]
    elif base['mnemonic'] == 'csrrw' or base['mnemonic'] == 'csrrs':
        base['sources'] = [number_register(base['operands'][2])]
        base['destination'] = number_register(base['operands'][0])
    elif base['mnemonic'] == 'csrwi':
        pass
    elif base['mnemonic'] == 'jal':
        base['is_constant_jump'] = True
        base['destination'] = number_register('ra')
    elif base['mnemonic'] == 'jalr':
        base['is_computed_jump'] = True
        if len(base['operands']) == 1:
            base['destination'] = number_register('ra')
            base['sources'] = [number_register(base['operands'][0])]
        elif len(base['operands']) == 2:
            base['destination'] = number_register(base['operands'][0])
            base['sources'] = [number_register(base['operands'][1])]
    elif base['mnemonic'] in rmw:
        base['destination'] = number_register(base['operands'][0])
        base['sources'] = [number_register(base['operands'][1]), number_register(base['operands'][2])]
        base['memory_read'] = True
        base['memory_write'] = True
    elif base['mnemonic'] in loads:
        base['destination'] = number_register(base['operands'][0])
        base['sources'] = [number_register(base['operands'][1])]
        base['memory_read'] = True
    elif base['mnemonic'] in stores:
        base['sources'] = [number_register(base['operands'][0]), number_register(base['operands'][1])]
        base['memory_write'] = True
    elif base['mnemonic'] in branches:
        base['is_conditional_branch'] = True
        base['destination'] = None
        base['sources'] = [number_register(operand) for operand in base['operands']]
    elif base['mnemonic'] == 'j':
        base['is_constant_jump'] = True
    elif base['mnemonic'] == 'jr':
        base['is_computed_jump'] = True
        base['sources'] = [number_register(base['operands'][0])]
    elif base['mnemonic'] == 'tval':
        pass
    elif base['mnemonic'] == 'fence':
        pass
    elif len(base['operands']) > 0:
        logger.debug('generic case for %s', base['mnemonic'])
        registers = []
        for operand in base['operands']:
            register = number_register(operand)
            registers.append(register)
        base['destination'] = registers[0]
        base['sources'] = registers[1:]
    return base

def convert_to_hcl_info(decoded):
    return {
        'orig_instruction': decoded['original'],
        'is_conditional_branch': 'Y' if decoded['is_conditional_branch'] else 'N',
        'is_constant_jump': 'Y' if decoded['is_constant_jump'] else 'N',
        'is_computed_jump': 'Y' if decoded['is_computed_jump'] else 'N',
        'srcA': decoded['sources'][0] if len(decoded['sources']) > 0 and decoded['sources'][0] != None else '',
        'srcB': decoded['sources'][1] if len(decoded['sources']) > 1 and decoded['sources'][1] != None else '',
        'dst': decoded['destination'] if decoded['destination'] != None else '',
        'is_memory_read': 'Y' if decoded['memory_read'] else 'N',
        'is_memory_write': 'Y' if decoded['memory_write'] else 'N',
    }

def parse_line(line):
    # core   0: 0x000000008000413c (0x07978763) beq     a5, s9, pc + 110
    m = re.match(r'core\s+0: 0x(?P<pc>[0-9a-f]+) \([^)]+\) (?P<instr>.*)', line)
    if m == None and line.startswith('D$'):
        m = re.match(r'D\$ (?P<access_type>read|write) miss 0x(?P<address>[0-9a-f]+)', line)
        if m != None:
            return {
                'type': 'miss',
                'access_type': m.group('access_type'),
                'address': int(m.group('address'), 16),
            }
        return None
    elif m == None and 'exception' in line:
        return None
    elif m == None and 'tval ' in line:
        return None
    elif m == None:
        raise Exception('malformed line {}'.format(line))
    logger.debug('found instruction %s', m.group('instr'))
    result = convert_to_hcl_info(decode_instruction(m.group('instr')))
    result['orig_pc'] = int(m.group('pc'), 16)
    result['orig_pc_part'] = '0'
    return {
        'type': 'instruction',
        'info': result,
    }

def raw_decoded_within(fh):
    for line in fh:
        yield parse_line(line)

def instructions_from(fh):
    last_cache_address = None
    pending_instruction = None
    for item in raw_decoded_within(fh):
        if item == None:
            continue
        if item['type'] == 'miss':
            assert pending_instruction != None and (
                pending_instruction['is_memory_read'] or
                pending_instruction['is_memory_write']
            ), 'cache miss should follow memory access instruction, not {}'.format(pending_instruction)
            last_cache_address = item['address']
            pending_instruction['mem_addr'] = last_cache_address
        elif item['type'] == 'instruction':
            if pending_instruction != None and pending_instruction['is_conditional_branch']:
                pending_instruction['branch_taken'] = (
                    'N' if item['info']['orig_pc'] in (
                        pending_instruction['orig_pc'] + 2,
                        pending_instruction['orig_pc'] + 4,
                    ) else 'Y'
                )
            elif pending_instruction != None:
                penidng_instruction['branch_taken'] = ''
            if pending_instruction != None:
                yield pending_instruction
            pending_instruction = item['info']
            if pending_instruction['is_memory_read'] or pending_instruction['is_memory_write']:
                pending_instruction['mem_addr'] = last_cache_address
        else:
            assert False, 'weird item {}'.format(item)
    if pending_instruction:
        yield pending_instruction


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--trace', nargs='?', type=argparse.FileType('r'))
    parser.add_argument('output', type=argparse.FileType('x'))
    args = parser.parse_args()
    writer = csv.DictWriter(args.output, FIELDS)
    writer.writeheader()
    for parsed in instructions_from(args.trace):
        if (parsed['is_memory_read'] or persed['is_memory_write']) and parsed['mem_addr'] == None:
            parsed['mem_addr'] = 0x0
        writer.writerow(parsed)
