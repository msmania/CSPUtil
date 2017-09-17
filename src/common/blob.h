class Blob {
private:
  HANDLE heap_;
  LPVOID buffer_;
  DWORD size_;

  void Release();

public:
  static Blob FromBase64String(LPCWSTR base64);
  static Blob FromHexString(LPCWSTR hexstr);
  static Blob AsUTF8(LPCWSTR plaintext);

  Blob();
  Blob(DWORD size);
  Blob(Blob &&other);
  ~Blob();

  operator PBYTE();
  operator LPCBYTE() const;
  Blob &operator=(Blob &&other);
  DWORD Size() const;
  bool Alloc(DWORD size);
  void Dump(std::wostream &os, size_t width, size_t ellipsis) const;
  bool Save(LPCWSTR filename) const;
  std::wstring ToBase64String() const;
  void Reverse();
};
