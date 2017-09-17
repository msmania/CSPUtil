#include <windows.h>
#include "csp.h"

void Log(LPCWSTR Format, ...);

void CSP::Release() {
  if (provider_) {
    CryptReleaseContext(provider_, 0);
  }
  provider_ = NULL;
}

CSP::CSP() : provider_(NULL) {}

CSP::~CSP() {
  Release();
}

CSP::operator HCRYPTPROV() {
  return provider_;
}

HCRYPTPROV CSP::Attach(HCRYPTPROV prov) {
  Release();
  return provider_ = prov;
}

bool CSP::Acquire(LPCWSTR containerName,
                  LPCWSTR providerName,
                  DWORD providerType,
                  DWORD flags) {
  Release();
  bool ret = !!CryptAcquireContext(&provider_,
                                   containerName,
                                   providerName,
                                   providerType,
                                   flags);
  if (!ret) {
    Log(L"CryptAcquireContext(%08x) failed - %08x\n",
        flags,
        GetLastError());
  }
  return ret;
}

HCRYPTKEY CSP::GetUserKey(DWORD keySpec) {
  HCRYPTKEY key = NULL;
  if (!CryptGetUserKey(provider_, keySpec, &key)) {
    Log(L"CryptGetUserKey() failed - %08x\n", GetLastError());
  }
  return key;
}
