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

#include "rc4.h"
#include <string.h>
#include <stdlib.h>

#ifndef NULL
#define NULL 0
#endif
void init(unsigned char *S)
{
	int i;

	for(i = 0; i < 256; i++)
		S[i] = i;
	return;
}

void swap(unsigned char *i, unsigned char *j)
{
	unsigned char temp;

	temp = *i;
	*i = *j;
	*j = temp;
}

void ksa(unsigned char *S, unsigned char *key, unsigned int keylen)
{
	int i, j;

	j = 0;
	for(i = 0; i < 256; i++)
	{
		j = (j + S[i] + key[i % keylen]) % 256;
		swap(&S[i], &S[j]);
	}
	return;
}

unsigned char* prng(unsigned char *S, int len)
{
	int i, j, k;
	unsigned char *keystream;

	keystream = (unsigned char*)malloc(sizeof(unsigned char) * (len+2));
	if (keystream == NULL)
		return NULL;

	i = 0;
	j = 0;
	for(k = 0; k < len; k++)
	{
		i = (i + 1) % 256;
		j = (j+S[i]) % 256;
		swap(&S[i], &S[j]);
#pragma warning( push )  
#pragma warning( disable : 6386 ) 
		keystream[k] = S[(S[i] + S[j]) % 256];
#pragma warning( pop )
	}
	return keystream;
}

void rc4(unsigned char *key,
		 unsigned int keySize, 
		 unsigned char *input, 
		 unsigned int inputSize, 
		 unsigned char *output)
{
	int i;
	unsigned char S[256];
	unsigned char *keystream;

	memset(S, 0, sizeof(S));
	init(S);
	ksa(S, key, keySize);
	keystream = prng(S, inputSize);

	if (keystream == NULL)
		return;

	for(i = 0; i < (int) inputSize; i++)
		output[i] = input[i] ^ keystream[i];

	memset(S, 0, 256); 
	free(keystream);
}