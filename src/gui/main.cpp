#include <windows.h>
#include <windowsx.h>
#include <strsafe.h>
#include <atlbase.h>
#include <shobjidl.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory>
#include "resource.h"
#include "..\common\csp.h"
#include "..\common\blob.h"
#include "..\common\key.h"
#include "..\common\hash.h"

void Log(LPCWSTR Format, ...) {
  WCHAR LineBuf[1024];
  va_list v;
  va_start(v, Format);
  StringCbVPrintf(LineBuf, sizeof(LineBuf), Format, v);
  va_end(v);
  OutputDebugString(LineBuf);
}

template<class T, class F>
static void for_each(std::initializer_list<T> list, F f) {
  for (auto &it : list) {
    f(it);
  }
}

class CMainDialog {
private:
  static CONST INT MAX_CONTAINER_NAME = 1024;

  static INT_PTR CALLBACK MainDlgProc(HWND dialog,
                                      UINT msg,
                                      WPARAM w,
                                      LPARAM l) {
    CMainDialog *p = nullptr;
    if (msg == WM_INITDIALOG) {
      SetWindowLongPtr(dialog, GWLP_USERDATA, l);
      p = reinterpret_cast<CMainDialog*>(l);
    }
    else {
      p = reinterpret_cast<CMainDialog*>(GetWindowLongPtr(dialog, GWLP_USERDATA));
    }
    return p ? p->MainDlgProcInternal(dialog, msg, w, l) : 0;
  }

  static void BuildErrorMessage(LPCWSTR message,
                                DWORD gle,
                                std::wstring &msg) {
    std::wstringstream ss;
    ss << message << L" - "
      << std::hex << std::setfill(L'0') << std::setw(8)
      << gle;
    msg = ss.str();
  }

  static std::wstring GetWindowText(HWND h) {
    std::wstring s;
    const auto len = GetWindowTextLength(h) + 1;
    if (auto buf = new WCHAR[len]) {
      if (::GetWindowText(h, buf, len) > 0) {
        s = buf;
      }
      delete [] buf;
    }
    return s;
  }

  class NameAndType {
  private:
    std::wstring name_;
    DWORD type_;
  public:
    NameAndType() : type_(0) {}
    NameAndType(LPCWSTR name, DWORD type) : name_(name), type_(type) {}
    NameAndType(const NameAndType &other)
      : name_(other.name_), type_(other.type_) {}
    LPCWSTR GetName() const {
      return type_ ? name_.c_str() : nullptr;
    }
    DWORD GetType() const {
      return type_;
    }
    std::wstring DisplayName() const {
      return type_ ? name_ + L"  (type: " + std::to_wstring(type_) + L")"
                   : L"(Default)";
    }
  };
  std::vector<NameAndType> validProviderTypes_;
  std::vector<NameAndType> validProviders_;

  const struct {
    ALG_ID id;
    LPCWSTR name;
  } validHashAlgos_[3] = {
    { CALG_MD5, L"MD5" },
    { CALG_SHA1, L"SHA1" },
    { CALG_SHA_256, L"SHA256" },
  };

  struct ContainerListCache {
    bool isForMachine_;
    DWORD providerType_;
    NameAndType providerName_;
    std::vector<std::wstring> names_;

    ContainerListCache() : isForMachine_(false), providerType_(0)
    {}

    ContainerListCache(bool isForMachine,
                       DWORD providerType,
                       const NameAndType &providerName)
      : isForMachine_(isForMachine),
        providerType_(providerType),
        providerName_(providerName)
    {}

    ContainerListCache &operator=(ContainerListCache &&other) {
      if (this != &other) {
        isForMachine_ = other.isForMachine_;
        providerType_ = other.providerType_;
        providerName_ = std::move(other.providerName_);
        names_ = std::move(other.names_);
      }
      return *this;
    }
  } activeContainerList_;

  CSP activeContainer_;
  CComPtr<IFileSaveDialog> savedialog_;

  enum KeyIndex : int {
    keySigPub = 0,
    keySigPri,
    keyExchgPub,
    keyExchgPri,
    keyMax,
  };
  const LPCWSTR defaultFileNames_[keyMax] = {
    L"exchg_pub",
    L"exchg_pri",
    L"sig_pub",
    L"sig_pri",
  };
  Blob keys_[keyMax];

  enum InputFormat : int {
    ifUtf8 = 0,
    ifHex,
    ifBase64,
    ifMax,
  };
  LPCWSTR validInputFormats_[ifMax] = {
    L"Plaintext in UTF-8",
    L"Hash in Hexstring",
    L"Hash in Base64-encode"
  };

  enum OutputFormat : int {
    ofHex = 0,
    ofBase64,
    ofMax,
  };
  LPCWSTR validOutputFormats_[ofMax] = {
    L"Hexstring",
    L"Base64-encode"
  };

  void InitFont() {
    if (!monoSpaceFont_) {
      HDC hdc = GetDC(dialog_);
      const auto size9pt = -MulDiv(9, GetDeviceCaps(hdc, LOGPIXELSY), 72);
      ReleaseDC(dialog_, hdc);

      LOGFONT font = {};
      font.lfHeight = size9pt;
      font.lfWeight = FW_NORMAL;
      StringCbCopy(font.lfFaceName, sizeof(font.lfFaceName), L"consolas");
      monoSpaceFont_ = CreateFontIndirect(&font);
      for_each({ editKeyExchangePub_, editKeySignaturePub_,
                 editKeyExchangePri_, editKeySignaturePri_,
                 editHash_, editSignature_ },
               [=](HWND h) {
                 SendMessage(h,
                             WM_SETFONT,
                             reinterpret_cast<WPARAM>(monoSpaceFont_), 0);
               });
    }
  }

  void InitProviderTypeList() {
    while (ListBox_DeleteString(comboProviderTypes_, 0) > 0);
    validProviderTypes_.clear();
    validProviderTypes_.push_back(NameAndType());

    DWORD type, len, i = 0;
    while (CryptEnumProviderTypes(i,
                                  /*pdwReserved*/nullptr,
                                  /*dwFlags*/0,
                                  &type,
                                  /*pszTypeName*/nullptr,
                                  &len)) {
      Blob nameBuffer(len);
      LPBYTE p = nameBuffer;
      if (p && CryptEnumProviderTypes(i++,
                                      /*pdwReserved*/nullptr,
                                      /*dwFlags*/0,
                                      &type,
                                      reinterpret_cast<LPWSTR>(p),
                                      &len)) {
        validProviderTypes_.push_back(NameAndType(reinterpret_cast<LPCWSTR>(p),
                                                  type));
      }
    }
    int initPos = 0;
    for (i = 0; i < validProviderTypes_.size(); ++i) {
      auto s = validProviderTypes_[i].DisplayName();
      ComboBox_AddString(comboProviderTypes_, s.c_str());
      if (validProviderTypes_[i].GetType() == PROV_RSA_AES) {
        initPos = i;
      }
    }
    ComboBox_SetCurSel(comboProviderTypes_, initPos);
  }

  void InitProviderNameList() {
    while (ListBox_DeleteString(comboProviderNames_, 0) > 0);
    validProviders_.clear();
    validProviders_.push_back(NameAndType());

    DWORD type, len, i = 0;
    while (CryptEnumProviders(i,
                              /*pdwReserved*/nullptr,
                              /*dwFlags*/0,
                              &type,
                              /*pszTypeName*/nullptr,
                              &len)) {
      Blob nameBuffer(len);
      LPBYTE p = nameBuffer;
      if (p && CryptEnumProviders(i++,
                                  /*pdwReserved*/nullptr,
                                  /*dwFlags*/0,
                                  &type,
                                  reinterpret_cast<LPWSTR>(p),
                                  &len)) {
        validProviders_.push_back(NameAndType(reinterpret_cast<LPCWSTR>(p),
                                              type));
      }
    }
    for (const auto &it : validProviders_) {
      auto s = it.DisplayName();
      ComboBox_AddString(comboProviderNames_, s.c_str());
    }
    ComboBox_SetCurSel(comboProviderNames_, 0);
  }

  void InitHashAlgorithms() {
    for (const auto &it : validHashAlgos_) {
      ComboBox_AddString(comboHashAlgos_, it.name);
    }
    ComboBox_SetCurSel(comboHashAlgos_, 2);
  }

  void InitFormatList() {
    for (const auto &it : validInputFormats_) {
      ComboBox_AddString(comboInputFormats_, it);
    }
    ComboBox_SetCurSel(comboInputFormats_, 0);

    for (const auto &it : validOutputFormats_) {
      ComboBox_AddString(comboOutputFormats_, it);
    }
    ComboBox_SetCurSel(comboOutputFormats_, 0);
  }

  void UpdateContainerList(bool true_if_machine) {
    auto index = ComboBox_GetCurSel(comboProviderTypes_);
    if (index < 0 && index >= static_cast<int>(validProviderTypes_.size()))
      return;
    const auto &selectedProviderType = validProviderTypes_[index];

    index = ComboBox_GetCurSel(comboProviderNames_);
    if (index < 0 && index >= static_cast<int>(validProviders_.size()))
      return;
    const auto &selectedProvider = validProviders_[index];

    while (ListBox_DeleteString(listContainers_, 0) > 0);

    activeContainerList_ = ContainerListCache(true_if_machine,
                                              selectedProviderType.GetType(),
                                              selectedProvider);
    DWORD flags = CRYPT_VERIFYCONTEXT;
    if (activeContainerList_.isForMachine_)
      flags |= CRYPT_MACHINE_KEYSET;

    CSP csp;
    if (csp.Acquire(/*containerName*/nullptr,
                    selectedProvider.GetName(),
                    selectedProviderType.GetType(),
                    flags)) {
      CHAR containerNameA[MAX_CONTAINER_NAME];
      WCHAR containerNameW[MAX_CONTAINER_NAME];
      DWORD bufferSize = sizeof(containerNameA);
      BOOL loop = CryptGetProvParam(csp,
                                    PP_ENUMCONTAINERS,
                                    reinterpret_cast<LPBYTE>(containerNameA),
                                    &bufferSize,
                                    CRYPT_FIRST);
      while (loop) {
        if (MultiByteToWideChar(CP_ACP,
                                0,
                                containerNameA,
                                -1,
                                containerNameW,
                                MAX_CONTAINER_NAME) > 0) {
          activeContainerList_.names_.push_back(containerNameW);
        }
        loop = CryptGetProvParam(csp,
                                 PP_ENUMCONTAINERS,
                                 reinterpret_cast<LPBYTE>(containerNameA),
                                 &bufferSize,
                                 CRYPT_NEXT);
      }
      std::sort(activeContainerList_.names_.begin(),
                activeContainerList_.names_.end());
      for (const auto &it : activeContainerList_.names_) {
        ListBox_AddString(listContainers_, it.c_str());
      }
    }
  }

  void UpdateKeyBlob(DWORD gle,
                     KeyIndex keyIndex,
                     HWND editBox,
                     HWND button,
                     Blob &&blob) {
    std::wstring message;
    EnableWindow(button, gle == ERROR_SUCCESS);
    if (gle == ERROR_SUCCESS) {
      std::wstringstream ss;
      blob.Dump(ss, /*width*/8, /*ellipsis*/100);
      SetWindowText(editBox, ss.str().c_str());
      keys_[keyIndex] = std::move(blob);
    }
    else {
      BuildErrorMessage(L"Failed to export the key", gle, message);
      SetWindowText(editBox, message.c_str());
    }
  }

  void OnSelectContainer() {
    auto index = ListBox_GetCurSel(listContainers_);
    LPCWSTR containerName =
      (index >= 0 && index < static_cast<int>(activeContainerList_.names_.size()))
        ? activeContainerList_.names_[index].c_str()
        : nullptr;
    if (!containerName) return;

    Edit_SetText(editContainerName_, containerName);

    DWORD flags = 0;
    if (activeContainerList_.isForMachine_)
      flags |= CRYPT_MACHINE_KEYSET;

    std::wstring message;
    CSP &csp = activeContainer_;
    if (csp.Acquire(containerName,
                    activeContainerList_.providerName_.GetName(),
                    activeContainerList_.providerType_,
                    flags)) {
      Key keyExchange(csp.GetUserKey(AT_KEYEXCHANGE));
      auto gle = GetLastError();
      if (keyExchange) {
        UpdateKeyBlob(GetLastError(),
                      keyExchgPub,
                      editKeyExchangePub_,
                      btnSaveKeyExchangePub_,
                      std::move(keyExchange.Export(PUBLICKEYBLOB)));
        UpdateKeyBlob(GetLastError(),
                      keyExchgPri,
                      editKeyExchangePri_,
                      btnSaveKeyExchangePri_,
                      std::move(keyExchange.Export(PRIVATEKEYBLOB)));
      }
      else {
        if (gle == NTE_NO_KEY) {
          for_each({ editKeyExchangePub_, editKeyExchangePri_ },
                   [](HWND h) { SetWindowText(h, L"No key"); });
        }
        else {
          BuildErrorMessage(L"Failed to get keys", gle, message);
          SetWindowText(editKeyExchangePub_, message.c_str());
          SetWindowText(editKeyExchangePri_, L"");
        }
        for_each({ btnSaveKeyExchangePub_, btnSaveKeyExchangePri_ },
                 [](HWND h) { EnableWindow(h, FALSE); });
      }

      Key keySignature(csp.GetUserKey(AT_SIGNATURE));
      gle = GetLastError();
      if (keySignature) {
        UpdateKeyBlob(GetLastError(),
                      keySigPub,
                      editKeySignaturePub_,
                      btnSaveKeySignaturePub_,
                      std::move(keySignature.Export(PUBLICKEYBLOB)));
        UpdateKeyBlob(GetLastError(),
                      keySigPri,
                      editKeySignaturePri_,
                      btnSaveKeySignaturePri_,
                      std::move(keySignature.Export(PRIVATEKEYBLOB)));
      }
      else {
        if (gle == NTE_NO_KEY) {
          for_each({ editKeySignaturePub_, editKeySignaturePri_ },
                   [](HWND h) { SetWindowText(h, L"No key"); });
        }
        else {
          BuildErrorMessage(L"Failed to get keys", gle, message);
          SetWindowText(editKeySignaturePub_, message.c_str());
          SetWindowText(editKeySignaturePri_, L"");
        }
        for_each({ btnSaveKeySignaturePub_, btnSaveKeySignaturePri_ },
                 [](HWND h) { EnableWindow(h, FALSE); });
      }
    }
    else {
      BuildErrorMessage(L"Failed to acquire the container", GetLastError(), message);
      SetWindowText(editKeyExchangePub_, message.c_str());
      for_each({ editKeyExchangePri_, editKeySignaturePub_, editKeySignaturePri_ },
               [](HWND h) { SetWindowText(h, L""); });
      for_each({ btnSaveKeyExchangePub_, btnSaveKeySignaturePub_,
                 btnSaveKeyExchangePri_, btnSaveKeySignaturePri_ },
               [](HWND h) { EnableWindow(h, FALSE); });
    }
  }

  bool ShowSaveDialog(LPCWSTR defaultName,
                      std::wstring &filepath) {
    bool ret = false;
    filepath = L"";
    if (savedialog_ == nullptr) {
      if (SUCCEEDED(savedialog_.CoCreateInstance(CLSID_FileSaveDialog))) {
        static const COMDLG_FILTERSPEC filetypes[] = {
          {L"BLOB", L"*"},
        };
        savedialog_->SetFileTypes(ARRAYSIZE(filetypes), filetypes);
      }
    }

    if (savedialog_) {
      savedialog_->SetFileName(defaultName);
      CComPtr<IShellItem> item;
      if (SUCCEEDED(savedialog_->Show(dialog_))
          && SUCCEEDED(savedialog_->GetResult(&item))) {
        LPWSTR displayName = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &displayName))) {
          ret = true;
          filepath = displayName;
          CoTaskMemFree(displayName);
        }
      }
    }
    return ret;
  }

  void SaveKey(KeyIndex keyIndex) {
    if (keyIndex >= 0 && keyIndex < keyMax) {
      std::wstring filepath;
      if (ShowSaveDialog(defaultFileNames_[keyIndex], filepath)) {
        const Blob &blob = keys_[keyIndex];
        if (!blob.Save(filepath.c_str())) {
          MessageBox(dialog_, L"Failed.", L"csputil", MB_OK);
        }
      }
    }
  }

  static Blob GenerateHash(ALG_ID algo, Blob blob) {
    CSP csp;
    if (csp.Acquire(nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
      HCRYPTHASH hHash = 0;
      if (CryptCreateHash(csp, algo, 0, 0, &hHash)) {
        Hash hash(hHash);
        if (hash.AddData(blob, blob.Size())) {
          return hash.GetHashValue();
        }
      }
    }
    return Blob();
  }

  void Sign() {
    const bool useExchgKey = !!IsDlgButtonChecked(dialog_, IDC_RADIO_EXCHANGE);
    const bool useSigKey = !!IsDlgButtonChecked(dialog_, IDC_RADIO_SIGNATURE);
    const auto algoIndex = ComboBox_GetCurSel(comboHashAlgos_);
    if (activeContainer_
        && (useExchgKey ^ useSigKey)
        && (algoIndex >= 0 && algoIndex < ARRAYSIZE(validHashAlgos_))) {
      const auto algo = validHashAlgos_[algoIndex].id;
      const auto keyType = useExchgKey ? AT_KEYEXCHANGE : AT_SIGNATURE;
      std::wstring message;
      HCRYPTHASH hHash = NULL;
      if (CryptCreateHash(activeContainer_, algo, /*hKey*/0, /*dwFlags*/0, &hHash)) {
        Hash hash(hHash);
        const auto hashStr = GetWindowText(editHash_);
        const auto inputFormat = ComboBox_GetCurSel(comboInputFormats_);
        const auto hashVal =
          inputFormat == ifBase64
          ? Blob::FromBase64String(hashStr.c_str())
          : inputFormat == ifHex
          ? Blob::FromHexString(hashStr.c_str())
          : inputFormat == ifUtf8
          ? GenerateHash(algo, Blob::AsUTF8(hashStr.c_str()))
          : Blob();
        if (hash.SetHashValue(hashVal, hashVal.Size())) {
          auto signature = hash.Sign(keyType);
          if (signature.Size() > 0) {
            if (IsDlgButtonChecked(dialog_, IDC_CHECK_FLIP)) {
              signature.Reverse();
            }
            const auto outputFormat = ComboBox_GetCurSel(comboOutputFormats_);
            if (outputFormat == ofHex) {
              std::wstringstream ss;
              signature.Dump(ss, /*width*/16, /*ellipsis*/4096);
              message = ss.str();
            }
            else if (outputFormat == ofBase64) {
              message = signature.ToBase64String();
            }
            else {
              message = L"Invalid format selected";
            }
          }
          else {
            BuildErrorMessage(L"Failed to generate a signature",
                              GetLastError(),
                              message);
          }
        }
        else {
          message = L"Invalid hash value";
        }
      }
      else {
        BuildErrorMessage(L"CryptCreateHash failed", GetLastError(), message);
      }
      SetWindowText(editSignature_, message.c_str());
    }
  }

  HWND dialog_;
  HWND comboProviderTypes_;
  HWND comboProviderNames_;
  HWND comboHashAlgos_;
  HWND comboInputFormats_;
  HWND comboOutputFormats_;
  HWND listContainers_;
  HWND editContainerName_;
  HWND editKeyExchangePub_;
  HWND editKeyExchangePri_;
  HWND editKeySignaturePub_;
  HWND editKeySignaturePri_;
  HWND editHash_;
  HWND editSignature_;
  HWND btnSaveKeyExchangePub_;
  HWND btnSaveKeyExchangePri_;
  HWND btnSaveKeySignaturePub_;
  HWND btnSaveKeySignaturePri_;
  HFONT monoSpaceFont_;

  INT_PTR MainDlgProcInternal(HWND dialog,
                              UINT msg,
                              WPARAM w,
                              LPARAM) {
    INT_PTR ret = 1;
    switch (msg) {
    case WM_INITDIALOG:
      dialog_ = dialog;
      comboProviderTypes_ = GetDlgItem(dialog, IDC_COMBO_PROVTYPE);
      comboProviderNames_ = GetDlgItem(dialog, IDC_COMBO_PROVNAME);
      comboHashAlgos_ = GetDlgItem(dialog, IDC_COMBO_HASH);
      comboInputFormats_ = GetDlgItem(dialog, IDC_COMBO_HASH_FORMAT);
      comboOutputFormats_ = GetDlgItem(dialog, IDC_COMBO_SIGNATURE_FORMAT);
      listContainers_ = GetDlgItem(dialog, IDC_LIST_CONTAINERS);
      editContainerName_ = GetDlgItem(dialog, IDC_EDIT_CONTAINERNAME);
      editKeyExchangePub_ = GetDlgItem(dialog_, IDC_EDIT_KEY_EXCHG_PUB);
      editKeyExchangePri_ = GetDlgItem(dialog_, IDC_EDIT_KEY_EXCHG_PRI);
      editKeySignaturePub_ = GetDlgItem(dialog_, IDC_EDIT_KEY_SIG_PUB);
      editKeySignaturePri_ = GetDlgItem(dialog_, IDC_EDIT_KEY_SIG_PRI);
      editHash_ = GetDlgItem(dialog_, IDC_EDIT_HASH);
      editSignature_ = GetDlgItem(dialog_, IDC_EDIT_SIGNATURE);
      btnSaveKeyExchangePub_ = GetDlgItem(dialog_, IDC_BTN_SAVE_EXCHG_PUB);
      btnSaveKeyExchangePri_ = GetDlgItem(dialog_, IDC_BTN_SAVE_EXCHG_PRI);
      btnSaveKeySignaturePub_ = GetDlgItem(dialog_, IDC_BTN_SAVE_SIG_PUB);
      btnSaveKeySignaturePri_ = GetDlgItem(dialog_, IDC_BTN_SAVE_SIG_PRI);
      InitProviderTypeList();
      InitProviderNameList();
      InitHashAlgorithms();
      InitFormatList();
      InitFont();
      break;
    case WM_COMMAND:
      switch (LOWORD(w)) {
      case IDCANCEL:
        EndDialog(dialog, IDCANCEL);
        break;
      case IDC_BTN_SEARCH_USER:
        UpdateContainerList(/*true_if_machine*/false);
        break;
      case IDC_BTN_SEARCH_MACHINE:
        UpdateContainerList(/*true_if_machine*/true);
        break;
      case IDC_LIST_CONTAINERS:
        if (HIWORD(w) == LBN_SELCHANGE) {
          OnSelectContainer();
        }
        else {
          ret = 0;
        }
        break;
      case IDC_BTN_SAVE_EXCHG_PUB:
        SaveKey(keyExchgPub);
        break;
      case IDC_BTN_SAVE_EXCHG_PRI:
        SaveKey(keyExchgPri);
        break;
      case IDC_BTN_SAVE_SIG_PUB:
        SaveKey(keySigPub);
        break;
      case IDC_BTN_SAVE_SIG_PRI:
        SaveKey(keySigPri);
        break;
      case IDC_BTN_SIGN:
        Sign();
        break;
      default:
        ret = 0;
      }
    default:
      ret = 0;
      break;
    }
    return ret;
  }

public:
  CMainDialog()
    : dialog_(nullptr),
      comboProviderTypes_(nullptr),
      comboProviderNames_(nullptr),
      comboHashAlgos_(nullptr),
      comboInputFormats_(nullptr),
      comboOutputFormats_(nullptr),
      listContainers_(nullptr),
      editContainerName_(nullptr),
      editKeyExchangePub_(nullptr),
      editKeyExchangePri_(nullptr),
      editKeySignaturePub_(nullptr),
      editKeySignaturePri_(nullptr),
      btnSaveKeyExchangePub_(nullptr),
      btnSaveKeyExchangePri_(nullptr),
      btnSaveKeySignaturePub_(nullptr),
      btnSaveKeySignaturePri_(nullptr),
      monoSpaceFont_(nullptr)
  {}

  ~CMainDialog() {
    if (monoSpaceFont_)
      DeleteObject(monoSpaceFont_);
  }

  int DoModal(HINSTANCE inst, int /*cmdshow*/) {
    DialogBoxParam(inst,
                   MAKEINTRESOURCE(IDD_MAIN),
                   nullptr,
                   MainDlgProc,
                   reinterpret_cast<LPARAM>(this));
    return 0;
  }
};

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int cmdshow) {
  const auto flags = COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE;
  if (SUCCEEDED(CoInitializeEx(nullptr, flags))) {
    if (auto dlg = std::make_unique<CMainDialog>()) {
      dlg->DoModal(inst, cmdshow);
    }
    CoUninitialize();
  }
  return 0;
}