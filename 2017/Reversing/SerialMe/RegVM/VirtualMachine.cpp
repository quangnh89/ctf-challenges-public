/**********************************************************************************/
// Copyright (C) 2017 Quang Nguyen https://develbranch.com
// The software included in this product contains copyrighted software that
// is licensed under the GPLv3. A copy of that license is included in this repository.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
/***********************************************************************************/
#define _CRT_SECURE_NO_WARNINGS 1
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "rc4.h"
#include "VirtualMachine.h"

#define  TEST_FLAG(x,f) (((x)&(f))==(f))
#define SET_FLAG(x,f) ((x)=(x)|(f))
#define CLR_FLAG(x,f) ((x)=(x)&(~f))

CVirtualMachine::CVirtualMachine(_In_ unsigned int memSize)
{
	memset(m_regs, 0, sizeof(m_regs));
	m_memSize = memSize;
	m_mem = new char[m_memSize];
}

CVirtualMachine::~CVirtualMachine()
{
	if (m_mem)
		delete[] m_mem;
}

void CVirtualMachine::Run(_In_ reg_t pc, _In_ int count /*= -1*/)
{
	m_regs[REG_EIP] = pc;
	int i = 0;
	for (; m_regs[REG_EIP] < m_memSize; )
	{
		if (TEST_FLAG(m_regs[REG_EFLAGS], VM_FLAG_HALT))
			break;
		if ((count > 0) && i > count)
			break;
		i++;
		char opcode = m_mem[m_regs[REG_EIP]];
		m_regs[REG_EIP]++;
		switch (opcode)
		{
		case INS_ADD:
			VmADD();
			break;
		case INS_SUB:
			VmSUB();
			break;
		case INS_XOR:
			VmXOR();
			break;
		case INS_AND:
			VmAND();
			break;
		case INS_OR:
			VmOR();
			break;
		case INS_NOT:
			VmNOT();
			break;
		case INS_ROTATE:
			VmROTATE();
			break;
		case INS_ZERO:
			VmZERO();
			break;
		case INS_CMP:
			VmCMP();
			break;
		case  INS_JZ:
			VmJZ();
			break;
		case INS_JNZ:
			VmJNZ();
			break;
		case INS_JMP:
			VmJMP();
			break;
		case INS_SYSCALL:
			VmSYSCALL();
			break;
		case INS_CRYPT:
			VmCRYPT();
			break;
		case INS_MOV_REG:
			VmMOV_REG();
			break;
		case INS_MOV_IMM:
			VmMOV_IMM();
			break;
		case INS_MOV_REG_MEM:
			VmMOV_REG_MEM();
			break;
		case INS_XCHG:
			VmXCHG();
			break;
		case INS_PUSH:
			VmPUSH();
			break;
		case INS_POP:
			VmPOP();
			break;
		case INS_HALT:
		default:
			VmHALT();
			break;
		}
	}
}

void CVirtualMachine::SetReg(_In_ int reg, _In_ reg_t value)
{
	if (reg >= REG_MAX)
		return;
	m_regs[reg] = value;
}

reg_t CVirtualMachine::GetReg(_In_ int reg)
{
	if (reg >= REG_MAX)
		return 0;
	return m_regs[reg];
}

unsigned int CVirtualMachine::WriteMem(_In_ address_t address, _In_ char* buffer, _In_ size_t n)
{
	if (address + n > m_memSize)
		return 0;
	memcpy(&m_mem[address], buffer, n);
	return (unsigned int)n;
}

#pragma warning( push )  
#pragma warning( disable : 6101 ) 
unsigned int CVirtualMachine::ReadMem(_In_ address_t address, _Out_ char* buffer, _In_ size_t n)
{
	if (address + n > m_memSize)
		return 0;
 
	memcpy(buffer, &m_mem[address], n);
	return (unsigned int)n;
}
#pragma warning( pop )  

void CVirtualMachine::debug_log(_In_ const char *fmt, ...)
{
	va_list arg;
	/* Write the error message */
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

void CVirtualMachine::SetZf(_In_ reg_t value)
{
	if (value == 0) {
		SET_FLAG(m_regs[REG_EFLAGS], VM_FLAG_ZF);
	}
	else {
		CLR_FLAG(m_regs[REG_EFLAGS], VM_FLAG_ZF);
	}
}

// add reg1, reg2
void CVirtualMachine::VmADD()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = m_regs[dst] + m_regs[src];
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmSUB()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = m_regs[dst] - m_regs[src];
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmXOR()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = m_regs[dst] ^ m_regs[src];
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmAND()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = m_regs[dst] & m_regs[src];
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmOR()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = m_regs[dst] | m_regs[src];
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmNOT()
{
	unsigned int dst;
	dst = m_mem[m_regs[REG_EIP]];
	m_regs[dst] = ~m_regs[dst];
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 1;
}

void CVirtualMachine::VmROTATE()
{
	unsigned int dst;
	dst = m_mem[m_regs[REG_EIP]];
	m_regs[dst] = (m_regs[dst] >> 4) | (m_regs[dst] << 28);
	SetZf(m_regs[dst]);
	m_regs[REG_EIP] += 1;
}

void CVirtualMachine::VmZERO()
{
	unsigned int dst;
	dst = m_mem[m_regs[REG_EIP]];
	m_regs[dst] = 0;
	m_regs[REG_EIP] += 1;
}

void CVirtualMachine::VmCMP()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	SetZf(m_regs[dst] - m_regs[src]);
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmJZ()
{
	if (TEST_FLAG(m_regs[REG_EFLAGS], VM_FLAG_ZF))
	{
		unsigned int delta = *(unsigned int*)&m_mem[m_regs[REG_EIP]];
		m_regs[REG_EIP] += (delta + 4);
	}
}

void CVirtualMachine::VmJNZ()
{
	if (!TEST_FLAG(m_regs[REG_EFLAGS], VM_FLAG_ZF))
	{
		unsigned int delta = *(unsigned int*)&m_mem[m_regs[REG_EIP]];
		m_regs[REG_EIP] += (delta + 4);
	}
}

void CVirtualMachine::VmJMP()
{
	unsigned int delta = *(unsigned int*)&m_mem[m_regs[REG_EIP]];
	m_regs[REG_EIP] += (delta + 4);
}

void CVirtualMachine::VmSYSCALL()
{
	reg_t func_index = m_regs[REG_EAX];
	if (func_index == VMSYSCALL_PUTS)
	{
		char *key = &m_mem[m_regs[REG_ESI]];
		m_regs[REG_EAX] = (reg_t)puts(key);
		return;
	}
	else if (func_index == VMSYSCALL_GETS)
	{
		char *buffer = &m_mem[m_regs[REG_EDI]];
		unsigned int n = m_regs[REG_ECX];
		fgets(buffer, n, stdin);
		char *p = strchr(buffer, '\n');
		if (p) *p = '\0';
		m_regs[REG_EAX] = (reg_t)strlen(buffer);
		return;
	}
	else if (func_index == VMSYSCALL_GETDWORD)
	{
		unsigned int n;
		if (EOF == scanf("%u%*c", &n))
		{
			VmHALT();
		}
		else
		{
			m_regs[REG_EAX] = (reg_t)n;
		}
		return;
	}

	m_regs[REG_EAX] = (reg_t)-1;
}

void CVirtualMachine::VmCRYPT()
{
	unsigned int keyLen = m_regs[REG_EDX];
	char *key = &m_mem[m_regs[REG_ECX]];
	unsigned int inputLen = m_regs[REG_EBX];
	char *input = &m_mem[m_regs[REG_ESI]];
	char *output = &m_mem[m_regs[REG_EDI]];
	rc4((unsigned char*)key, keyLen, (unsigned char*)input, inputLen, (unsigned char*)output);
}

void CVirtualMachine::VmMOV_REG()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = m_regs[src];
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmMOV_IMM()
{
	unsigned int dst;
	dst = m_mem[m_regs[REG_EIP]];
	unsigned int value = *(unsigned int*)&m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = value;
	m_regs[REG_EIP] += 5;
}

void CVirtualMachine::VmMOV_REG_MEM()
{
	unsigned int dst;
	dst = m_mem[m_regs[REG_EIP]];
	unsigned int offset = *(unsigned int*)&m_mem[m_regs[REG_EIP] + 1];
	m_regs[dst] = *(reg_t*)&m_mem[offset];
	m_regs[REG_EIP] += 5;
}

void CVirtualMachine::VmXCHG()
{
	unsigned int dst, src;
	dst = m_mem[m_regs[REG_EIP]];
	src = m_mem[m_regs[REG_EIP] + 1];
	reg_t temp = m_regs[dst];
	m_regs[dst] = m_regs[src];
	m_regs[src] = temp;
	m_regs[REG_EIP] += 2;
}

void CVirtualMachine::VmPUSH()
{
	unsigned int src = m_mem[m_regs[REG_EIP]];
	m_regs[REG_ESP] -= sizeof(reg_t);
	*(unsigned int*)&m_mem[m_regs[REG_ESP]] = m_regs[src];
	m_regs[REG_EIP] += 1;
}

void CVirtualMachine::VmPOP()
{
	unsigned int dst = m_mem[m_regs[REG_EIP]];
	m_regs[dst] = *(unsigned int*)&m_mem[m_regs[REG_ESP]];
	m_regs[REG_ESP] += sizeof(reg_t);
	m_regs[REG_EIP] += 1;
}

void CVirtualMachine::VmHALT()
{
	SET_FLAG(m_regs[REG_EFLAGS], VM_FLAG_HALT);
}
