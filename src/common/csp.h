class CSP {
private:
  HCRYPTPROV provider_;

  void Release();

public:
  CSP();
  ~CSP();
  operator HCRYPTPROV();
  HCRYPTPROV Attach(HCRYPTPROV prov);
  bool Acquire(LPCWSTR containerName,
               LPCWSTR providerName,
               DWORD providerType,
               DWORD flags);
  HCRYPTKEY GetUserKey(DWORD keySpec);
};
