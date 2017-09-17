class Hash {
private:
  HCRYPTHASH hash_;

  void Release();

public:
  Hash();
  Hash(HCRYPTHASH hash);
  ~Hash();
  operator HCRYPTHASH();
  void Attach(HCRYPTHASH hash);
  bool AddData(LPCBYTE data, DWORD dataLength);
  bool SetHashValue(LPCBYTE data, DWORD dataLength);
  Blob GetHashValue() const;
  Blob Sign(DWORD keyType);
  bool Verify(LPCBYTE signature,
              DWORD signatureLength,
              HCRYPTKEY publicKey);
};
