// MIT License
//
// Copyright (c) 2025 DataCrypt - xmc0211 <xmc0211@qq.com>xmc0211
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef DATACRYPT_H
#define DATACRYPT_H

#include <Windows.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

// AES key structure used for this library
struct AESKEY {
	BYTE* key;
	DWORD len;
	AESKEY();
	AESKEY(const AESKEY& other);
	~AESKEY();
};

// Get text length after AES encrypt
DWORD AESGetLenAfterEncrypt(DWORD dwOriginalLen);

// Encrypt data. Provide plaintext, key, and iv.
BOOL AESEncryptData(BYTE* lpData, DWORD* EncryptLen, DWORD BufferSize, const AESKEY AESKey, const BYTE iv[AES_BLOCK_SIZE]);

// Encrypt data. Provide ciphertext, key, and iv.
BOOL AESDecryptData(BYTE* lpData, DWORD* EncryptLen, const AESKEY AESKey, const BYTE iv[AES_BLOCK_SIZE]);

// Create a random number. Cannot be used as a key. 
BOOL AESCreateRandomNumber(BYTE* lpData, size_t sz);

// Create an AES key.
BOOL AESCreateRandomKey(AESKEY* key);

#endif