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
    'is_computed_jump',
    'is_constant_jump',
    'srcA',
    'srcB',
    'dst',
    'is_memory_read',
    'is_memory_write',
    'mem_addr',
    'branch_taken',
]


def translate_register_y86(reg_id):
    if reg_id == 0xf:
        return ''
    else:
        return reg_id

def extract_records_from_y86(args, wire_table):
    wire_table_lines = wire_table.split('\n')
    wires = {}
    for line in wire_table_lines:
        parts = re.split(r'\s+', line, maxsplit=2)
        if len(parts) < 2:
            logging.debug('skipping with parts = %s', parts)
            continue
        key = parts[0]
        value = parts[1]
        if not value.startswith('0x'):
            logger.debug('ignoring key/value = %s/%s', key, value)
            continue
        logger.debug('about to convert %s', value)
        wires[key] = int(value[2:], 16)
    kinds = {
        0x0: 'halt',
        0x1: 'nop',
        0x2: 'rrmovq',
        0x3: 'irmovq',
        0x4: 'rmmovq',
        0x5: 'mrmovq',
        0x6: 'OPq',
        0x7: 'jXX',
        0x8: 'call',
        0x9: 'ret',
        0xa: 'pushq',
        0xb: 'popq',
    }
    logger.debug('found wires %s', wires)
    branch_taken = 'Y' if wires['x_pc'] == wires['valC'] else 'N'
    kind = kinds[wires['icode']]
    if kind == 'jXX' and wires['ifun'] == '0':
        kind = 'jmp'
    elif args.simplify and kind == 'pushq':
        # simulate as OPq + rmmovq
        yield {
            'orig_instruction': 'pushq',
            'orig_pc': wires['pc'],
            'orig_pc_part': 0,
            'is_conditional_branch': 'N',
            'is_computed_jump': 'N',
            'is_constant_jump': 'N',
            'srcA': translate_register_y86(wires['reg_srcA']),
            'dst': translate_register_y86(wires['reg_dstE']),
            'is_memory_read': 'N',
            'is_memory_write': 'N',
            'mem_addr': '',
        }
        yield {
            'orig_instruction': 'pushq',
            'orig_pc': wires['pc'],
            'orig_pc_part': 1,
            'is_conditional_branch': 'N',
            'is_computed_jump': 'N',
            'is_constant_jump': 'N',
            'srcA': translate_register_y86(wires['reg_srcB']),
            'is_memory_read': 'N',
            'is_memory_write': 'Y',
            'mem_addr': hex(wires['mem_addr']),
        }
    elif kind == 'popq':
        # simulate as OPq + mrmovq
        yield {
            'orig_instruction': 'popq',
            'orig_pc': wires['pc'],
            'orig_pc_part': 0,
            'is_conditional_branch': 'N',
            'is_computed_jump': 'N',
            'is_constant_jump': 'N',
            'srcA': translate_register_y86(wires['reg_srcA']),
            'dst': translate_register_y86(wires['reg_dstE']),
            'is_memory_read': 'N',
            'is_memory_write': 'N',
            'mem_addr': '',
        }
        yield {
            'orig_instruction': 'popq',
            'orig_pc': wires['pc'],
            'orig_pc_part': 1,
            'is_conditional_branch': 'N',
            'is_computed_jump': 'N',
            'is_constant_jump': 'N',
            'srcA': translate_register_y86(wires['reg_srcB']),
            'dst': translate_register_y86(wires['reg_dstM']),
            'is_memory_read': 'N',
            'is_memory_write': 'Y',
            'mem_addr': hex(wires['mem_addr']),
        }
    elif args.simplify and kind == 'call':
        # simulate as rmmovq + jmp
        yield {
            'orig_instruction': 'call',
            'orig_pc': wires['pc'],
            'orig_pc_part': 0,
            'is_conditional_branch': 'N',
            'is_computed_jump': 'N',
            'is_constant_jump': 'N',
            'srcA': translate_register_y86(wires['reg_srcA']),
            'srcB': translate_register_y86(wires['reg_srcB']),
            'is_memory_read': 'N',
            'is_memory_write': 'Y',
            'mem_addr': hex(wires['mem_addr']),
        }
        yield {
            'orig_instruction': 'call',
            'orig_pc': wires['pc'],
            'orig_pc_part': 1,
            'is_conditional_branch': 'N',
            'is_computed_jump': 'N',
            'is_constant_jump': 'Y',
            'branch_taken': '',
            'is_memory_read': 'N',
            'is_memory_write': 'N',
            'mem_addr': '',
        }
    elif args.simplify and kind == 'ret':
         # simulate as mrmovq + jmp
         yield {
             'orig_instruction': 'ret',
             'orig_pc': wires['pc'],
             'orig_pc_part': 0,
             'mem_addr': hex(wires['mem_addr']),
             'dst': 16,
             'is_conditional_branch': 'N',
             'is_computed_jump': 'N',
             'is_constant_jump': 'N',
             'is_memory_read': 'Y',
             'is_memory_write': 'N',
         }
         yield {
             'orig_instruction': 'ret',
             'orig_pc': wires['pc'],
             'orig_pc_part': 1,
             'is_conditional_branch': 'N',
             'is_computed_jump': 'N',
             'is_constant_jump': 'Y',
             'branch_taken': '',
             'srcA': 16,
             'is_memory_read': 'N',
             'is_memory_write': 'N',
         }
    else:
        yield {
            'orig_pc': wires['pc'],
            'orig_pc_part': 0,
            'is_conditional_branch': 'Y' if kind == 'jXX' else 'N',
            'is_constant_jump': 'Y' if kind == 'jmp' or kind == 'call' else 'N',
            'is_computed_jump': 'Y' if kind == 'ret' else 'N',
            'branch_taken': branch_taken if kind == 'jXX' else '',
            'srcA': translate_register_y86(wires['reg_srcA']),
            'srcB': translate_register_y86(wires['reg_srcB']),
            'dst': translate_register_y86(wires['reg_dstE'] if wires['reg_dstE'] != 0xF else wires['reg_dstM']),
            'is_memory_read': 'Y' if wires['mem_readbit'] else 'N',
            'is_memory_write': 'Y' if wires['mem_writebit'] else 'N',
            'mem_addr': hex(wires['mem_addr']) if wires['mem_readbit'] or wires['mem_writebit'] else '',
        }

def parts_from_file_hcl(in_file):
    current = []
    in_wires = False
    for line in in_file:
        if line.startswith('Values of inputs'):
            logger.debug('found start %s', line)
            current = []
            in_wires = True
        elif line.startswith('+--') and in_wires:
            in_wires = False
            logger.debug('about to yield %s', current)
            yield '\n'.join(current)
        elif in_wires:
            logger.debug('found middle %s', line)
            current.append(line)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--hcl4-solution', default='../hcl-grader/solutions/sln4_seqhw.hcl')
    parser.add_argument('--hclrs', default='../hclrs-dist/hclrs')
    parser.add_argument('--simplify', default=False, action='store_true')
    parser.add_argument('--input-debug', nargs='?', type=argparse.FileType('r'))
    parser.add_argument('--yo', nargs='?', type=argparse.FileType('r'))
    parser.add_argument('output', type=argparse.FileType('x'))
    args = parser.parse_args()
    process = None
    if args.yo:
        process = subprocess.run(
            [args.hclrs,
             args.hcl4_solution,
             '-d',
             args.yo.name
            ],
            stdout=subprocess.PIPE,
            stderr=None,
            encoding='UTF-8',
            errors='replace',
        )
        hcl_output = process.stdout.split('\n')
    else:
        hcl_output = args.input_debug
    writer = csv.DictWriter(args.output, FIELDS)
    writer.writeheader()
    for part in parts_from_file_hcl(hcl_output):
        for record in extract_records_from_y86(args, part):
            writer.writerow(record)
