class Key {
private:
  HCRYPTKEY key_;

  void Release();

public:
  Key();
  Key(HCRYPTKEY key);
  ~Key();

  void Attach(HCRYPTKEY key);
  operator HCRYPTKEY();
  Blob Export(DWORD blobType);
};
