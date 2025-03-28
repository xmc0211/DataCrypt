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

#include "DataCrypt.h"

AESKEY::AESKEY() : key(NULL), len(AES_KEY_SIZE) {

}

AESKEY::AESKEY(const AESKEY& other) : len(other.len) {
    key = (BYTE*)VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_READWRITE);
    if (key == NULL || other.key == NULL) return;
    memcpy(key, other.key, len);
}

AESKEY::~AESKEY() {
    if (key) {
        VirtualFree(key, 0, MEM_RELEASE);
        key = NULL;
    }
}

DWORD AESGetLenAfterEncrypt(DWORD dwOriginalLen) {
    return (dwOriginalLen + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1);
}

BOOL AESEncryptData(BYTE* lpData, DWORD* EncryptLen, DWORD BufferSize, const AESKEY AESKey, const BYTE iv[AES_BLOCK_SIZE]) {
    if (lpData == NULL || EncryptLen == NULL || iv == NULL) return FALSE;
    AESKEY key(AESKey);
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL bRes = FALSE;
    DWORD RealLen = *EncryptLen;

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptImportKey(hProv, key.key, key.len, 0, 0, &hKey)) goto EXIT;
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) goto EXIT;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, lpData, &RealLen, BufferSize)) goto EXIT;
    *EncryptLen = RealLen;
    bRes = TRUE;

EXIT:
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return bRes;
}

BOOL AESDecryptData(BYTE* lpData, DWORD* EncryptLen, const AESKEY AESKey, const BYTE iv[AES_BLOCK_SIZE]) {
    if (lpData == NULL || EncryptLen == NULL || iv == NULL) return FALSE;
    AESKEY key(AESKey);
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL bRes = FALSE;
    DWORD RealLen = *EncryptLen;

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptImportKey(hProv, key.key, key.len, 0, 0, &hKey)) goto EXIT;
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) goto EXIT;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, lpData, &RealLen)) goto EXIT;
    *EncryptLen = RealLen;
    bRes = TRUE;

EXIT:
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return bRes;
}

BOOL AESCreateRandomNumber(BYTE* lpData, size_t sz) {
    if (lpData == NULL) return FALSE;
    HCRYPTPROV hProv = 0;
    BOOL bRes = FALSE;
    DWORD keyLen = sz;

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (CryptGenRandom(hProv, keyLen, lpData)) bRes = TRUE;

    CryptReleaseContext(hProv, 0);
    return bRes;
}

BOOL AESCreateRandomKey(AESKEY* key) {
    if (key == NULL) return FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL bRes = FALSE;

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) goto EXIT;
    if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &(key->len))) goto EXIT;
    key->key = (BYTE*)VirtualAlloc(NULL, key->len, MEM_COMMIT, PAGE_READWRITE);
    if (!key->key) goto EXIT;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, key->key, &(key->len))) goto EXIT;
    bRes = TRUE;

EXIT:
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    if (key->key && !bRes) VirtualFree(key->key, 0, MEM_RELEASE);
    return bRes;
}
