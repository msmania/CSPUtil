#include <windows.h>
#include <strsafe.h>
#include <iostream>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <blob.h>

void Log(LPCWSTR Format, ...) {
  WCHAR LineBuf[1024];
  va_list v;
  va_start(v, Format);
  StringCbVPrintf(LineBuf, sizeof(LineBuf), Format, v);
  va_end(v);
  OutputDebugString(LineBuf);
}

TEST(Blob, Load) {
  const BYTE utf8[] = {0xE3, 0x83, 0xA9, 0xE3, 0x83, 0xBC, 0xE3, 0x83,
                       0xA1, 0xE3, 0x83, 0xB3};
  auto blob = Blob::AsUTF8(L"\u30E9\u30FC\u30E1\u30F3");
  EXPECT_EQ(blob.Size(), sizeof(utf8));
  EXPECT_EQ(memcmp(blob, utf8, sizeof(utf8)), 0);
  ASSERT_STREQ(blob.ToBase64String().c_str(), L"44Op44O844Oh44Oz\r\n");

  blob = Blob::FromBase64String(L"44Op44O844Oh44Oz");
  EXPECT_EQ(blob.Size(), sizeof(utf8));
  EXPECT_EQ(memcmp(blob, utf8, sizeof(utf8)), 0);

  blob = Blob::FromHexString(L"E3 83 A9 E3 83 BC E3 83 A1 E3 83 B3");
  EXPECT_EQ(blob.Size(), sizeof(utf8));
  EXPECT_EQ(memcmp(blob, utf8, sizeof(utf8)), 0);

  blob = Blob::FromHexString(L"E383A9E383BCE383A1E383B3");
  EXPECT_EQ(blob.Size(), sizeof(utf8));
  EXPECT_EQ(memcmp(blob, utf8, sizeof(utf8)), 0);

  blob = Blob::FromHexString(L"E3:83:A9:E3:83:BC:E3:83:A1:E3:83:B3");
  EXPECT_EQ(blob.Size(), sizeof(utf8));
  EXPECT_EQ(memcmp(blob, utf8, sizeof(utf8)), 0);

  blob = Blob::FromHexString(L"xxx");
  EXPECT_EQ(blob.Size(), 0);
  EXPECT_EQ(LPCBYTE(blob), nullptr);
}

TEST(Blob, Dump) {
  Blob blob(42);
  for (DWORD i = 0; i < blob.Size(); ++i) {
    blob[i] = static_cast<BYTE>(i);
  }

  std::wstringstream ss1;
  blob.Dump(ss1, /*width*/12, /*ellipsis*/100);
  ASSERT_STREQ(ss1.str().c_str(),
               L"Total: 42 (=0x2a) bytes\r\n"
               L"0000: 00 01 02 03 04 05 06 07  08 09 0a 0b\r\n"
               L"000c: 0c 0d 0e 0f 10 11 12 13  14 15 16 17\r\n"
               L"0018: 18 19 1a 1b 1c 1d 1e 1f  20 21 22 23\r\n"
               L"0024: 24 25 26 27 28 29");

  std::wstringstream ss2;
  blob.Dump(ss2, /*width*/12, /*ellipsis*/10);
  ASSERT_STREQ(ss2.str().c_str(),
               L"Total: 42 (=0x2a) bytes\r\n"
               L"0000: 00 01 02 03 04 05 06 07  08 09 ...\r\n");
}
