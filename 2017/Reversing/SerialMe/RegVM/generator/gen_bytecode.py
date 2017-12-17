# -------------------------------------------------------------------------------
# Name:      gen_bytecode.py
# Purpose:   generate bytecode for Simple VM engine
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
from engine import *
from rc4 import rc4_crypt

flag = 'Submit this flag: svattt{An0th3rFr3akVirtualMach1n3}'


def rotate(x):
    return (((x >> 4) | (x << 28)) & 0xffffffff)


def check_code_1(c):
    code = ''
    code += assembler_line('MOV_IMM eax, 0x4')  # GETDWORD
    code += assembler_line('syscall')
    code += assembler_line('push eax')
    code += assembler_line('MOV_IMM ebx, 0x478236a4')
    code += assembler_line('XOR eax, ebx')
    code += assembler_line('NOT eax')
    code += assembler_line('MOV_IMM ebx, 0x%x' % ((~(c[0] ^ 0x478236a4)) & 0xffffffff))
    code += assembler_line('CMP eax, ebx')
    code += assembler_line('XCHG eax, eax')  # NOP
    code += assembler_line('JZ 1')  # Skip 1 byte
    code += assembler_line('HALT')

    code += assembler_line('MOV_IMM eax, 0x4')  # GETDWORD 2
    code += assembler_line('syscall')
    code += assembler_line('push eax')
    code += assembler_line('MOV_IMM ebx, 0x478236a4')
    code += assembler_line('ADD eax, ebx')
    code += assembler_line('MOV_IMM ebx, 0xabd475c1')
    code += assembler_line('XOR eax, ebx')
    code += assembler_line('MOV_IMM ecx, 0x%x' % (((c[1] + 0x478236a4) ^ 0xabd475c1) & 0xffffffff))
    code += assembler_line('CMP eax, ecx')
    code += assembler_line('XCHG eax, eax')  # NOP
    code += assembler_line('JZ 1')  # Skip 1 byte
    code += assembler_line('HALT')

    code += assembler_line('MOV_IMM eax, 0x4')  # GETDWORD 3
    code += assembler_line('syscall')
    code += assembler_line('push eax')
    code += assembler_line('MOV_IMM ebx, 0x57834ADC')
    code += assembler_line('SUB eax, ebx')
    code += assembler_line('MOV_IMM ebx, 0x437294AA')
    code += assembler_line('XOR eax, ebx')
    code += assembler_line('ROTATE eax')
    code += assembler_line('MOV_IMM edx, 0x%x' % (rotate((c[2] - 0x57834ADC) ^ 0x437294AA) & 0xffffffff))
    code += assembler_line('CMP eax, edx')
    code += assembler_line('XCHG eax, eax')  # NOP
    code += assembler_line('JZ 1')  # Skip 1 byte
    code += assembler_line('HALT')

    code += assembler_line('MOV_IMM eax, 0x4')  # GETDWORD 4
    code += assembler_line('syscall')
    code += assembler_line('push eax')
    code += assembler_line('MOV_IMM ebx, 0x78912d5d')
    code += assembler_line('ADD eax, ebx')
    code += assembler_line('MOV_IMM esi, 0x%x' % (((c[3] + 0x78912d5d)) & 0xffffffff))
    code += assembler_line('CMP eax, esi')
    code += assembler_line('XCHG eax, eax')  # NOP
    code += assembler_line('JZ 1')  # Skip 1 byte
    code += assembler_line('HALT')

    code += assembler_line('MOV_IMM eax, 0x4')  # GETDWORD 5
    code += assembler_line('syscall')
    code += assembler_line('push eax')
    code += assembler_line('MOV_IMM ebx, 0x4561A234')
    code += assembler_line('SUB eax, ebx')
    code += assembler_line('MOV_IMM edi, 0x%x' % (((c[4] - 0x4561A234)) & 0xffffffff))
    code += assembler_line('CMP eax, edi')
    code += assembler_line('XCHG eax, eax')  # NOP
    code += assembler_line('JZ 1')  # Skip 1 byte
    code += assembler_line('HALT')

    return code


def build_crypt_code(plain, key, build_check_code=None):
    cipher = rc4_crypt(plain, key)
    code = ''
    key_len = len(key)

    while (len(key) % 4) != 0:
        key += '\x00'
    d = [key[i:i + 4] for i in range(0, len(key), 4)]

    c = []
    for _ in d:
        c.append((ord(_[0]) + (ord(_[1]) << 8) + (ord(_[2]) << 16) + (ord(_[3]) << 24)))
    c = c[::-1]

    if build_check_code is None:
        # mov eax, imm; push eax
        for _ in c:
            code += assembler_line('MOV_IMM eax, 0x%x' % _)
            code += assembler_line('push eax')
    else:
        code += build_check_code(c)

    code += assembler_line('MOV_IMM edx, 0x%x' % key_len)
    code += assembler_line('MOV_IMM ebx, 0x%x' % len(plain))
    code += assembler_line('MOV_REG ecx, esp')
    code += assembler_line('MOV_IMM eax, 0x%x' % (len(c) * 4))
    code += assembler_line('ADD esp, eax')
    code += assembler_line('MOV_REG esi, eip')
    code += assembler_line('MOV_IMM eax, 15')
    code += assembler_line('ADD esi, eax')
    code += assembler_line('MOV_REG edi, esi')
    code += assembler_line('CRYPT')
    code += cipher
    return code


flag += '\x00'

while (len(flag) % 4) != 0:
    flag += '\x00'

data = [flag[i:i + 4] for i in range(0, len(flag), 4)]

converted_flag = []

for _ in data:
    converted_flag.append(ord(_[0]) + (ord(_[1]) << 8) + (ord(_[2]) << 16) + (ord(_[3]) << 24))
converted_flag = converted_flag[::-1]

bytecode = ''

# generate mov eax, imm; push eax
for _ in converted_flag:
    bytecode += assembler_line('MOV_IMM eax, 0x%x' % _)
    bytecode += assembler_line('push eax')

bytecode += assembler_line('MOV_REG esi, esp')
bytecode += assembler_line('MOV_IMM eax, 0x%x' % (len(converted_flag) * 4))
bytecode += assembler_line('ADD esp, eax')
bytecode += assembler_line('MOV_IMM eax, 2')  # puts
bytecode += assembler_line('syscall')  # puts
bytecode += assembler_line('halt')  # halt

bytecode = build_crypt_code(bytecode, 'FAKmEgnbwYycOVmYErg7', check_code_1)
bytecode = build_crypt_code(bytecode, 'FlXRg5LERkkwAS9TnPMB', check_code_1)

open('bytecode.bin', 'wb').write(bytecode)