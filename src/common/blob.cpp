#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "blob.h"

void Log(LPCWSTR Format, ...);

template<class ST, class CH>
class bstream {
private:
  std::stringstream ss_;
  int half_char;

  void add_char(CH c) {
    int h = 0;
    if (c >= '0' && c <= '9')
      h = c - '0';
    else if (c >= 'A' && c <= 'F')
      h = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
      h = c - 'a' + 10;
    else
      return;

    if (half_char < 0) {
      half_char = h;
    }
    else {
      ss_ << static_cast<unsigned char>(half_char << 4 | h);
      half_char = -1;
    }
  }

public:
  bstream() : half_char(-1) {}

  void operator << (const ST &line) {
    for (auto c : line) {
      add_char(c);
    }
  }

  void operator << (CH ch) {
    add_char(ch);
  }

  std::string get() const {
    return ss_.str();
  }

  void flush() {
    ss_.str("");
    half_char = -1;
  }
};

void Blob::Release() {
  if (buffer_) {
    HeapFree(heap_, 0, buffer_);
    buffer_ = nullptr;
    size_ = 0;
  }
}

Blob Blob::FromBase64String(LPCWSTR base64) {
  Blob blob;
  DWORD decodedLength = 0;
  if (CryptStringToBinary(base64,
                          0,
                          CRYPT_STRING_BASE64,
                          nullptr,
                          &decodedLength,
                          nullptr,
                          nullptr)
      && blob.Alloc(decodedLength)) {
    if (!CryptStringToBinary(base64,
                             0,
                             CRYPT_STRING_BASE64,
                             blob,
                             &decodedLength,
                             nullptr,
                             nullptr)) {
      Log(L"CryptStringToBinary failed - %08x\n", GetLastError());
      blob.Release();
    }
  }
  return blob;
}

Blob Blob::FromHexString(LPCWSTR hexstr) {
  Blob blob;
  if (!hexstr) return blob;

  bstream<std::wstring, wchar_t> bs;
  auto p = hexstr;
  while (*p) {
    bs << *(p++);
  }

  auto bstr = bs.get();
  if (blob.Alloc(static_cast<int>(bstr.size()))) {
    bstr.copy(reinterpret_cast<LPSTR>(LPBYTE(blob)), bstr.size());
  }
  return blob;
}

Blob Blob::AsUTF8(LPCWSTR plaintext) {
  Blob blob;
  size_t len = 0;
  HRESULT hr = StringCchLength(plaintext, STRSAFE_MAX_CCH, &len);
  if (FAILED(hr)) {
    Log(L"StringCchLength failed - %08x\n", hr);
    return blob;
  }
  auto bytesNeeded = WideCharToMultiByte(CP_UTF8,
                                         0,
                                         plaintext,
                                         static_cast<int>(len),
                                         nullptr,
                                         0,
                                         nullptr,
                                         nullptr);
  if (bytesNeeded > 0 && blob.Alloc(bytesNeeded)) {
    if (WideCharToMultiByte(CP_UTF8,
                            0,
                            plaintext,
                            static_cast<int>(len),
                            reinterpret_cast<LPSTR>(LPBYTE(blob)),
                            bytesNeeded,
                            nullptr,
                            nullptr) != bytesNeeded) {
      Log(L"WideCharToMultiByte failed - %08x\n", GetLastError());
      blob.Release();
    }
  }
  return blob;
}

Blob::Blob()
  : heap_(GetProcessHeap()),
    buffer_(nullptr),
    size_(0)
{}

Blob::Blob(DWORD size)
  : heap_(GetProcessHeap()),
    buffer_(nullptr),
    size_(0)
{
  Alloc(size);
}

Blob::Blob(Blob &&other)
  : heap_(GetProcessHeap()),
    buffer_(nullptr),
    size_(0) {
  std::swap(buffer_, other.buffer_);
  std::swap(heap_, other.heap_);
  std::swap(size_, other.size_);
}

Blob::~Blob() {
  Release();
}

Blob::operator PBYTE() {
  return reinterpret_cast<PBYTE>(buffer_);
}

Blob::operator LPCBYTE() const {
  return reinterpret_cast<LPCBYTE>(buffer_);
}

Blob &Blob::operator=(Blob &&other) {
  if (this != &other) {
    Release();
    heap_ = other.heap_;
    buffer_ = other.buffer_;
    size_ = other.size_;
    other.buffer_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

DWORD Blob::Size() const {
  return size_;
}

bool Blob::Alloc(DWORD size) {
  if (buffer_) {
    buffer_ = HeapReAlloc(GetProcessHeap(), 0, buffer_, size);
    if (buffer_) {
      size_ = size;
    }
    else {
      Log(L"HeapReAlloc failed - %08x\n", GetLastError());
    }
  }
  else if (size > 0) {
    buffer_ = HeapAlloc(GetProcessHeap(), 0, size);
    if (buffer_) {
      size_ = size;
    }
    else {
      Log(L"HeapAlloc failed - %08x\n", GetLastError());
    }
  }
  return buffer_ != nullptr;
}

void Blob::Dump(std::wostream &os, size_t width, size_t ellipsis) const {
  if (auto p = reinterpret_cast<LPCBYTE>(buffer_)) {
    os << L"Total: " << size_ << L" (=0x"
       << std::hex << size_ << L") bytes\r\n";

    size_t bytesLeft = min(size_, ellipsis);
    int lineCount = 0;
    while (bytesLeft) {
      size_t i;
      for (i = 0; bytesLeft && i < width; ++i) {
        if (i == 0)
          os << std::hex << std::setfill(L'0') << std::setw(4)
             << (lineCount * width) << L':';

        if (i > 0 && i % 8 == 0)
          os << L"  " << std::hex << std::setfill(L'0') << std::setw(2) << *(p++);
        else
          os << L' ' << std::hex << std::setfill(L'0') << std::setw(2) << *(p++);

        --bytesLeft;
      }
      ++lineCount;
      if (i == width) os << L"\r\n";
    }

    if (size_ > ellipsis)
      os << L" ...\r\n";
  }
}

bool Blob::Save(LPCWSTR filename) const {
  bool ret = false;
  if (auto p = reinterpret_cast<LPCBYTE>(buffer_)) {
    HANDLE file = CreateFile(filename,
                             GENERIC_WRITE,
                             FILE_SHARE_READ,
                             nullptr,
                             OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (file != INVALID_HANDLE_VALUE) {
      DWORD bytesWritten = 0;
      ret = !!WriteFile(file, p, size_, &bytesWritten, nullptr);
      if (!ret) {
        Log(L"WriteFile failed - %08x\n", GetLastError());
      }
      CloseHandle(file);
    }
    else {
      Log(L"CreateFile(%s) failed - %08x\n", filename, GetLastError());
    }
  }
  return ret;
}

std::wstring Blob::ToBase64String() const {
  std::wstring ret;
  DWORD characters = 0;
  if (CryptBinaryToString(reinterpret_cast<LPCBYTE>(buffer_),
                          size_,
                          CRYPT_STRING_BASE64,
                          nullptr,
                          &characters)
      && characters > 0) {
    if (auto buf = new WCHAR[characters]) {
      if (CryptBinaryToString(reinterpret_cast<LPCBYTE>(buffer_),
                              size_,
                              CRYPT_STRING_BASE64,
                              buf,
                              &characters)) {
        ret = buf;
      }
      delete[] buf;
    }
  }
  return ret;
}

void Blob::Reverse() {
  if (auto p = reinterpret_cast<LPBYTE>(buffer_)) {
    std::reverse(p, p + size_);
  }
}
