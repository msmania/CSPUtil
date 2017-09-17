#include <windows.h>
#include <iostream>
#include "blob.h"
#include "hash.h"

void Log(LPCWSTR Format, ...);

void Hash::Release() {
  if (hash_) {
    CryptDestroyHash(hash_);
  }
  hash_ = NULL;
}

Hash::Hash() : hash_(NULL) {}

Hash::Hash(HCRYPTHASH hash) : hash_(NULL) {
  Attach(hash);
}

Hash::~Hash() {
  Release();
}

Hash::operator HCRYPTHASH() {
  return hash_;
}

void Hash::Attach(HCRYPTHASH hash) {
  Release();
  hash_ = hash;
}

bool Hash::AddData(LPCBYTE data, DWORD dataLength) {
  bool ret = !!CryptHashData(hash_, data, dataLength, 0);
  if (!ret) {
    Log(L"CryptHashData failed - %08x\n", GetLastError());
  }
  return ret;
}

bool Hash::SetHashValue(LPCBYTE data, DWORD dataLength) {
  bool ret = false;
  DWORD hashSize = 0;
  DWORD size = sizeof(hashSize);
  if (CryptGetHashParam(hash_,
                        HP_HASHSIZE,
                        reinterpret_cast<LPBYTE>(&hashSize),
                        &size,
                        0)) {
    if (hashSize == dataLength) {
      ret = !!CryptSetHashParam(hash_, HP_HASHVAL, data, 0);
      if (!ret) {
        Log(L"CryptSetHashParam failed - %08x\n", GetLastError());
      }
    }
    else {
      SetLastError(ERROR_INVALID_DATA);
      Log(L"Hash size does not match\n", GetLastError());
    }
  }
  else {
    Log(L"CryptGetHashParam failed - %08x\n", GetLastError());
  }
  return ret;
}

Blob Hash::GetHashValue() const {
  Blob blob;
  DWORD hashLen = 0;
  if (hash_
      && CryptGetHashParam(hash_, HP_HASHVAL, nullptr, &hashLen, 0)
      && blob.Alloc(hashLen)) {
    if (!CryptGetHashParam(hash_, HP_HASHVAL, blob, &hashLen, 0)) {
      Log(L"CryptGetHashParam failed - %08x\n", GetLastError());
    }
  }
  return blob;
}

Blob Hash::Sign(DWORD keyType) {
  Blob blob;
  DWORD len = 0;
  if(CryptSignHash(hash_,
                   keyType,
                   nullptr,
                   0,
                   nullptr,
                   &len))
  {
    if (blob.Alloc(len)) {
      if(!CryptSignHash(hash_,
                        keyType,
                        nullptr,
                        0,
                        blob,
                        &len))
      {
        Log(L"CryptSignHash#2 failed - %08x\n", GetLastError());
      }
    }
  }
  else
  {
    Log(L"CryptSignHash#1 failed - %08x\n", GetLastError());
  }
  return blob;
}

bool Hash::Verify(LPCBYTE signature,
                  DWORD signatureLength,
                  HCRYPTKEY publicKey) {
  bool ret = !!CryptVerifySignature(hash_,
                                    signature,
                                    signatureLength,
                                    publicKey,
                                    nullptr,
                                    0);
  if (!ret) {
    Log(L"CryptVerifySignature failed - %08x\n", GetLastError());
  }
  return ret;
}
