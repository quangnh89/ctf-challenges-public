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
#pragma once
typedef unsigned int reg_t;
typedef unsigned int address_t;

// declare register ID
enum {
	REG_EAX,
	REG_EBX,
	REG_ECX,
	REG_EDX,
	REG_ESI,
	REG_EDI,
	REG_EBP,
	REG_EIP,
	REG_ESP,
	REG_EFLAGS,
	REG_MAX
};

//declare syscall table
enum VM_SYSCALL_TABLE
{
	VMSYSCALL_GETCHAR, // read a character from stdin, NOT IMPLEMENTED
	VMSYSCALL_PUTCHAR, // write a character to stdout, NOT IMPLEMENTED
	VMSYSCALL_PUTS,    // put a string, ESI points to string
	VMSYSCALL_GETS,    // read a string, EDI points to memory region containing data copied 
	VMSYSCALL_GETDWORD,// read a 32-bit number from stdin, EAX stores the result
};

// declare flags
enum VM_FLAG
{
	VM_FLAG_HALT = 1 << 0,
	VM_FLAG_ZF = 1 << 1, //ZERO flag
	VM_FLAG_SYS_ERR = 1 << 2, // something is wrong when executing syscall
	VM_FLAG_BNR = 1 << 3,// branch without return
};

// declare virtual machine instruction
enum VM_INS
{
	INS_ADD = 0,
	INS_SUB,
	INS_XOR,
	INS_AND,
	INS_OR,
	INS_NOT,
	INS_ROTATE,
	INS_ZERO,
	INS_CMP,
	INS_JZ,
	INS_JNZ,
	INS_JMP,
	INS_SYSCALL,
	INS_CRYPT,
	INS_MOV_REG,
	INS_MOV_IMM,
	INS_MOV_REG_MEM,
	INS_XCHG,
	INS_PUSH,
	INS_POP,
	INS_HALT,
	INS_MAX
};

// declare Virtual machine class
class CVirtualMachine
{
protected:
	reg_t m_regs[REG_MAX];
	char* m_mem;
	unsigned int m_memSize;
public:
	
	// Initialize a new virtual machine
	// memSize: memory size of machine
	CVirtualMachine(_In_ unsigned int memSize);

	// cleanup and release machine
	virtual ~CVirtualMachine();

	// Start virtual machine
	// pc: memory address where virtual machine starts
	// count: the number of instructions to be run. When this value is -1
	//   we will run all the code available, until the code is finished
	void Run(_In_ reg_t pc, _In_ int count = -1);

	// set value to register
	// reg: register ID
	// value: the value that will set to register
	void SetReg(_In_ int reg, _In_ reg_t value);

	// get value from register
	// reg: register ID
	// function returns register value
	reg_t GetReg(_In_ int reg);

	// Write to a range of bytes in memory.
	// address: starting memory address of bytes to set
	// buffer: pointer to a variable containing data to be written to memory.
	// n: size of memory to write to
	unsigned int WriteMem(_In_ address_t address, _In_ char* buffer, _In_ size_t n);

	// Read a range of bytes in memory.
	// address: starting memory address of bytes to get
	// buffer: pointer to a variable containing data copied from memory.
	// n: size of memory to read.
	unsigned int ReadMem(_In_ address_t address, _Out_ char* buffer, _In_ size_t n);

protected:
	// show log 
	void debug_log(_In_ const char *fmt, ...);

	// set ZERO flag
	void SetZf( _In_ reg_t value);

	void VmADD(); // add reg1, reg2
	void VmSUB(); // sub reg1, reg2
	void VmXOR(); // xor reg1, reg2
	void VmAND(); // and reg1, reg2
	void VmOR();  // or  reg1, reg2
	void VmNOT(); // not reg
	void VmROTATE(); // rotate reg, 4
	void VmZERO(); // reg = 0
	void VmCMP(); // cmp  reg1, reg2
	void VmJZ();  // jmp to address if ZERO flag is set
	void VmJNZ(); // jmp to address if ZERO flag is NOT set
	void VmJMP(); // jmp to address
	void VmSYSCALL();// syscall
	void VmCRYPT(); // crypt
	void VmMOV_REG(); // MOV reg1, reg2
	void VmMOV_IMM(); // mov reg, immediate
	void VmMOV_REG_MEM(); // mov reg, [offset]
	void VmXCHG(); // XCHG reg1, reg2
	void VmPUSH(); // push reg
	void VmPOP();  // pop reg
	void VmHALT(); // halt: stop everything
};
