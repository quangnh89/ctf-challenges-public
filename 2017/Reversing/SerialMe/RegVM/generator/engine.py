# -------------------------------------------------------------------------------
# Name:      engine.py
# Purpose:   assembler and disassembler for Simple VM engine
#
# Copyright (C) 2017 Quang Nguyen https://develbranch.com
# The software included in this product contains copyrighted software that
# is licensed under the GPLv3. A copy of that license is included in this repository.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
# -------------------------------------------------------------------------------
import re
import struct
import sys
import getopt
import ntpath


mnemonic_list = [
    "ADD",
    "SUB",
    "XOR",
    "AND",
    "OR",
    "NOT",
    "ROTATE",
    "ZERO",
    "CMP",
    "JZ",
    "JNZ",
    "JMP",
    "SYSCALL",
    "CRYPT",
    "MOV_REG",
    "MOV_IMM",
    "MOV_REG_MEM",
    "XCHG",
    "PUSH",
    "POP",
    "HALT", ]

mnemonic = {mnemonic_list[index]: chr(index) for index in range(len(mnemonic_list))}
opcode = {chr(index): mnemonic_list[index] for index in range(len(mnemonic_list))}

r = [
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "EIP",
    "ESP",
    "EFLAGS",
]

reg_mnemonic = {r[index]: chr(index) for index in range(len(r))}
reg_opcode = {chr(index): r[index] for index in range(len(r))}


def disassembler(binary):
    source = ''
    i = 0
    while i < len(binary):
        source += '0x%04x  ' % (i)
        j = i
        instruction = ''
        if not binary[i] in opcode:
            instruction += 'db %02X' % (ord(binary[i]))
            i += 1
        else:
            m = opcode[binary[i]]
            instruction += m + ' '
            i += 1
            if m == 'MOV_IMM':
                instruction += hex(struct.unpack('<I', binary[i: i + 4])[0])
                i += 4
            elif m in ('JZ', 'JNZ', 'BRANCH'):
                delta = ((struct.unpack('<I', binary[i: i + 4])[0]) & 0xffffffff)
                label = ((i + delta + 4) & 0xffffffff)
                instruction += '0x%04x' % (label)
                i += 4
        bytecode = binary[j: i]
        bytecodestr = ''
        for c in bytecode:
            bytecodestr += '%02X ' % ord(c)
        if len(bytecodestr) < 16:
            bytecodestr += ' ' * (16 - len(bytecodestr))
        source += bytecodestr + instruction + '\n'
    return source


def assembler_line(line):
    binary = ''
    # line_token = re.split('; |, |\*|\n|\s+|\t', line)
    line_token = re.split('[\s,]+', line)
    m = line_token[0].upper()
    if m in mnemonic:
        binary += mnemonic[m]
        token_index = 1
        if len(line_token) > 1 and line_token[token_index].upper() in reg_mnemonic:
            binary += reg_mnemonic[line_token[token_index].upper()]
            token_index += 1

        if m == 'MOV_IMM' or m == 'JMP' or m == 'JE' or m == 'JNE' or m == 'JZ' or m == 'JNZ':
            if line_token[token_index].find('0x') == 0:
                binary += struct.pack('<I', int(line_token[token_index], 16))
            elif line_token[token_index].find("'") == 0:
                binary += struct.pack('<I', ord(line_token[token_index].strip("'")))
            else:
                binary += struct.pack('<I', int(line_token[token_index], 10))
        elif m in ['MOV_REG', "ADD", "SUB", "XOR", "AND", "OR", "XCHG", 'CMP']:
            try:
                binary += reg_mnemonic[line_token[token_index].upper()]
            except:
                raise Exception('Syntax error: ' + line)
    else:
        raise Exception('Syntax error')
    return binary


def assembler(source_file):
    binary = ''
    labels = {}
    s = open(source_file, 'rt')
    line_count = 0
    scan_counter = 0
    while True:
        if scan_counter == 2:
            break
        binary = ''
        s.seek(0, 0)
        line_count = 0
        while True:
            line = s.readline()
            if line is None or line == '':
                break
            line_count += 1
            if line.startswith('#'):
                continue
            line = line.strip()
            if line.find('#') != -1:
                line = line[:line.find('#')]
            if len(line) == 0:
                continue
            if line.startswith('db ') or line.startswith('DB '):
                literal = line[3:]
                try:
                    binary += eval('str(' + literal + ')')
                except Exception as e:
                    raise Exception('Syntax error: line ' + str(line_count) + 'error:' + str(e))
                continue
            if line.find(':') != -1:
                # label
                l = re.split(':', line)
                if len(l) > 2:
                    raise Exception('Syntax error: review label, line ' + str(line_count))
                if l[0] in labels and scan_counter == 0:
                    raise Exception('Syntax error: Duplicate label, line ' + str(line_count))
                else:
                    labels[l[0]] = len(binary)
                continue

            else:
                # line_token = re.split('; |, |\*|\n|\s+|\t', line)
                line_token = re.split('[\s,]+', line)
                m = line_token[0].upper()
                if m in ('JZ', 'JE', 'JNZ', 'JNE', 'BRANCH'):
                    if not labels.has_key(line_token[1]) and scan_counter > 0:
                        raise Exception('Syntax error: Label not found, line ' + str(line_count))
                    else:
                        if scan_counter > 0:
                            delta = labels[line_token[1]] - (len(binary) + 4)
                        else:
                            delta = 0
                        binary += struct.pack('<I', delta & 0xffffffff)
                elif m in mnemonic:
                    binary = assembler_line(line)
                else:
                    raise Exception('Syntax error: line ' + str(line_count))
        scan_counter += 1

    s.close()
    return binary


def usage():
    print
    print 'Usage: ' + ntpath.basename(__file__) + ' [-d] [-h] [--output-file output] source'
    print 'Mandatory arguments to long options are mandatory for short options too.'
    print '-d, --disassemble            disassemble mode'
    print '-h, --help                   display this help and exit'
    print '-o, --output-file, --output  destination file'
    sys.exit(0)


def main():
    disasm_mode = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hdo:', ['output-file=', 'output=', 'help', 'disassemble'])
        output_file = ''
        for o, a in opts:
            if o in ('-h', 'help'):
                usage()

            if o in ('-d', '--disassemble'):
                disasm_mode = True
            if o in ("-o", "--output", '--output-file'):
                output_file = a

        if (len(args) == 0):
            print 'No input file'
            usage()
            sys.exit(0)
        input_file = args[0]
        print 'Input file:', input_file
        print
        if not disasm_mode:
            binary = assembler(input_file)
            if len(output_file) > 0:
                print "output file:", output_file
                open(output_file, "wb").write(binary)
            else:
                print 'Binary code:'
                for c in binary:
                    sys.stdout.write('%02x' % ord(c))
                print
        else:
            binary = open(input_file, 'rb').read()
            source = disassembler(binary)
            if len(output_file) > 0:
                print "output file:", output_file
                open(output_file, "wt").write(source)
            else:
                print source

    except Exception as e:
        print e
        return


if __name__ == '__main__':
    main()
