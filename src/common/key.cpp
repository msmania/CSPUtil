#include <windows.h>
#include <iostream>
#include "blob.h"
#include "key.h"

void Log(LPCWSTR Format, ...);

void Key::Release() {
  if (key_) {
    CryptDestroyKey(key_);
  }
  key_ = NULL;
}

Key::Key() : key_(NULL)
{}

Key::Key(HCRYPTKEY key) : key_(NULL) {
  Attach(key);
}

Key::~Key() {
  Release();
}

void Key::Attach(HCRYPTKEY key) {
  Release();
  key_ = key;
}

Key::operator HCRYPTKEY() {
  return key_;
}

Blob Key::Export(DWORD blobType) {
  Blob blob;
  if (key_) {
    DWORD len = 0;
    if (CryptExportKey(key_,
      NULL,
      blobType,
      0,
      nullptr,
      &len)) {
      if (blob.Alloc(len)) {
        if (CryptExportKey(key_,
                           NULL,
                           blobType,
                           0,
                           blob,
                           &len)) {
          SetLastError(0);
        }
        else {
          Log(L"CryptExportKey failed - %08x\n", GetLastError());
        }
      }
    }
    else {
      Log(L"CryptExportKey failed - %08x\n", GetLastError());
    }
  }
  return blob;
}
