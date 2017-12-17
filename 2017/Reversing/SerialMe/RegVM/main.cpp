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
#include <stdio.h>
#include "VirtualMachine.h"
unsigned char bytecode[616] = {
	0x0F, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x0F, 0x01, 0xA4, 0x36, 0x82, 0x47, 0x02,
	0x00, 0x01, 0x05, 0x00, 0x0F, 0x01, 0x35, 0x99, 0x30, 0xFA, 0x08, 0x00, 0x01, 0x11, 0x00, 0x00,
	0x09, 0x01, 0x00, 0x00, 0x00, 0x14, 0x0F, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x0F,
	0x01, 0xA4, 0x36, 0x82, 0x47, 0x00, 0x00, 0x01, 0x0F, 0x01, 0xC1, 0x75, 0xD4, 0xAB, 0x02, 0x00,
	0x01, 0x0F, 0x02, 0x24, 0xFC, 0x6F, 0x30, 0x08, 0x00, 0x02, 0x11, 0x00, 0x00, 0x09, 0x01, 0x00,
	0x00, 0x00, 0x14, 0x0F, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x0F, 0x01, 0xDC, 0x4A,
	0x83, 0x57, 0x01, 0x00, 0x01, 0x0F, 0x01, 0xAA, 0x94, 0x72, 0x43, 0x02, 0x00, 0x01, 0x06, 0x00,
	0x0F, 0x03, 0x4D, 0xAB, 0xC9, 0xC5, 0x08, 0x00, 0x03, 0x11, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00,
	0x00, 0x14, 0x0F, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x0F, 0x01, 0x5D, 0x2D, 0x91,
	0x78, 0x00, 0x00, 0x01, 0x0F, 0x04, 0xC4, 0x62, 0xDD, 0xBD, 0x08, 0x00, 0x04, 0x11, 0x00, 0x00,
	0x09, 0x01, 0x00, 0x00, 0x00, 0x14, 0x0F, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x0F,
	0x01, 0x34, 0xA2, 0x61, 0x45, 0x01, 0x00, 0x01, 0x0F, 0x05, 0x12, 0xCA, 0xF6, 0x0C, 0x08, 0x00,
	0x05, 0x11, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x14, 0x0F, 0x03, 0x14, 0x00, 0x00, 0x00,
	0x0F, 0x01, 0x76, 0x01, 0x00, 0x00, 0x0E, 0x02, 0x08, 0x0F, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x0E, 0x04, 0x07, 0x0F, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0E, 0x05,
	0x04, 0x0D, 0x53, 0xAF, 0xB2, 0x8E, 0xF4, 0x3B, 0xDB, 0x78, 0xE2, 0x67, 0x0E, 0x7D, 0xE6, 0xAD,
	0x29, 0xF4, 0x43, 0x3C, 0xBD, 0xA2, 0x85, 0x5E, 0x15, 0x00, 0x9D, 0x55, 0xD8, 0x0F, 0x36, 0x18,
	0x35, 0x9C, 0x50, 0x29, 0x08, 0x17, 0x09, 0x93, 0x02, 0xD0, 0xE5, 0xAC, 0xA2, 0xA5, 0xA4, 0x51,
	0x3A, 0xA5, 0xE9, 0x38, 0x41, 0xD3, 0xD5, 0x7B, 0xCB, 0xD0, 0x81, 0xDC, 0xF6, 0x3E, 0xFE, 0xBA,
	0xF7, 0x7F, 0xA5, 0x93, 0x39, 0x70, 0x74, 0xDA, 0x70, 0x56, 0xA2, 0x5D, 0xBC, 0xC8, 0x92, 0x17,
	0x69, 0x56, 0x24, 0x63, 0xF9, 0xF3, 0x73, 0xE5, 0x1D, 0x64, 0xC8, 0xEA, 0x16, 0xC1, 0x69, 0x5D,
	0x1E, 0x3A, 0x97, 0x3D, 0x0E, 0x0E, 0x3F, 0xFD, 0xCD, 0x93, 0xC8, 0xF3, 0x29, 0xED, 0x42, 0xD7,
	0xDA, 0x27, 0x19, 0xD1, 0xC6, 0x51, 0x8D, 0x67, 0xC4, 0xB5, 0x04, 0xB4, 0xD3, 0x41, 0x63, 0x23,
	0x4A, 0xB5, 0x9A, 0xA2, 0x9A, 0x2F, 0xFC, 0x16, 0x5A, 0x9D, 0xC7, 0x4B, 0x86, 0xB4, 0x0E, 0xE8,
	0x12, 0xFA, 0x22, 0xE3, 0x4B, 0xBA, 0xB1, 0x52, 0xE7, 0xBD, 0x23, 0x8E, 0x4C, 0x85, 0xF0, 0xB1,
	0xD6, 0xAD, 0xF3, 0xBB, 0xD3, 0x3D, 0x08, 0xE8, 0xF0, 0xE5, 0x8F, 0x56, 0x5B, 0x32, 0x93, 0xDE,
	0x9A, 0x74, 0x2C, 0xD9, 0xBE, 0xBA, 0x19, 0xEE, 0x9A, 0xDE, 0xEE, 0xEA, 0x97, 0x9C, 0x51, 0xC5,
	0x43, 0xBE, 0xD4, 0x8B, 0xF4, 0xEA, 0xB4, 0xDC, 0xB0, 0x41, 0x9C, 0x55, 0x77, 0x82, 0xC8, 0x03,
	0x0D, 0x7A, 0x28, 0xB0, 0xBA, 0x36, 0xEC, 0x3C, 0xD2, 0xE7, 0x11, 0x98, 0x71, 0xB8, 0xF9, 0xA1,
	0xD2, 0xEF, 0x5B, 0x72, 0x68, 0x45, 0xA9, 0x1D, 0x19, 0x6C, 0xD8, 0xB2, 0x55, 0x9E, 0xCE, 0xD3,
	0xFB, 0xB9, 0xE8, 0x8B, 0x13, 0xD8, 0x7F, 0x80, 0xB7, 0x41, 0x75, 0x2F, 0xB1, 0xE2, 0x7E, 0x7A,
	0xDC, 0x5B, 0x2A, 0x29, 0x95, 0xC1, 0x24, 0x8F, 0x65, 0xFB, 0xDC, 0xF1, 0xD8, 0xDA, 0x1E, 0x19,
	0x2E, 0x71, 0x2D, 0xE5, 0xB0, 0x7A, 0x67, 0x95, 0x6F, 0x00, 0xC6, 0xB0, 0x86, 0xB1, 0x59, 0x9A,
	0x5D, 0x67, 0x78, 0xA7, 0x0B, 0xCF, 0x4F, 0x8A, 0xB5, 0x86, 0xAE, 0x9E, 0x57, 0x19, 0x9A, 0x26,
	0xF5, 0xAD, 0xB1, 0x4F, 0x00, 0xD7, 0xE4, 0x7B, 0x90, 0x1D, 0xA5, 0x4A, 0x2A, 0xC2, 0xB8, 0x11,
	0xC4, 0xA6, 0xD8, 0x88, 0x33, 0x41, 0xFD, 0x8A, 0xDA, 0x79, 0x30, 0x7A, 0x25, 0x53, 0x49, 0xE2,
	0xF0, 0x7A, 0xE4, 0xDA, 0xE8, 0x0B, 0x0F, 0xB4, 0xD4, 0x55, 0xE9, 0xCA, 0x6E, 0xC1, 0x5E, 0x12,
	0xE1, 0xDA, 0x08, 0xC6, 0xA7, 0xDE, 0xE0, 0xC4, 0x2F, 0x09, 0xBA, 0xDB, 0xB2, 0x61, 0x13, 0x28,
	0xD3, 0xA4, 0x4C, 0xE2, 0x69, 0x60, 0xD7, 0x6C
};

void Welcome() {
	printf("\n");
	printf(" _____           _       _                  \n");
	printf("/  ___|         (_)     | |                 \n");
	printf("\\ `--.  ___ _ __ _  __ _| |  _ __ ___   ___ \n");
	printf(" `--. \\/ _ \\ '__| |/ _` | | | '_ ` _ \\ / _ \\\n");
	printf("/\\__/ /  __/ |  | | (_| | | | | | | | |  __/\n");
	printf("\\____/ \\___|_|  |_|\\__,_|_| |_| |_| |_|\\___|\n");
	printf("\n");
	printf("\n");
	printf("Designed by Quang Nguyen(quangnh89), a member of VNSECURITY. My blog: https://develbranch.com\n");
	printf("Description: You need to provide 10 numbers and get the flag. Good luck!\n");
	printf("\n");
}

int main(int argc, char**argv)
{
	Welcome();
	const unsigned int nSize = 0x2000;
	CVirtualMachine * vm = new CVirtualMachine(nSize);
	if (vm)
	{
		if (argc == 2)
		{
			FILE *f = fopen(argv[1], "rb");
			fseek(f, 0, SEEK_END);
			long n = ftell(f);
			fseek(f, 0, SEEK_SET);
			fread(bytecode, 1, n < sizeof(bytecode) ? n : sizeof(bytecode), f);
			fclose(f);
		}

		vm->WriteMem(0, (char*)bytecode, sizeof(bytecode));
		vm->SetReg(REG_ESP, nSize / 2);
		vm->Run(0, -1);

		delete vm;
	}
	return 0;
}