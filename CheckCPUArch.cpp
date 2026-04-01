// CheckCPUArch.cpp : Scans a directory for .exe/.dll files and reports their PE CPU architecture.

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <cctype>
#include <windows.h>

namespace fs = std::filesystem;

static bool g_verbose = false;

void printUsage(const char* exe) {
    std::cout << "Usage: " << exe << " [-s] [-v] [path]\n"
              << "\n"
              << "Scans for .exe and .dll files and reports their PE CPU architecture.\n"
              << "\n"
              << "Options:\n"
              << "  -s or /s   Scan all sub-folders recursively\n"
              << "  -v or /v   Enable verbose trace output\n"
              << "  path       Directory to scan (defaults to current directory)\n";
}

std::string getArchName(WORD machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:       return "x86";
    case IMAGE_FILE_MACHINE_AMD64:      return "x64";
    case IMAGE_FILE_MACHINE_ARM:        return "ARM";
    case IMAGE_FILE_MACHINE_ARMNT:      return "ARM (Thumb-2)";
    case IMAGE_FILE_MACHINE_ARM64:      return "Arm64";
    case 0xA641:                        return "Arm64X";
    case 0xA64E:                        return "Arm64EC";
    case IMAGE_FILE_MACHINE_IA64:       return "IA-64";
    default: {
        char buf[32];
        snprintf(buf, sizeof(buf), "Unknown (0x%04X)", machine);
        return buf;
    }
    }
}

struct FileResult {
    std::string relativePath;
    std::string architecture;
};

std::string determineArchitecture(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        if (g_verbose) std::cerr << "  [verbose] Cannot open file: " << filePath.string() << "\n";
        return "Error: cannot open";
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader{};
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        if (g_verbose) std::cerr << "  [verbose] Not a valid PE file (bad DOS signature): " << filePath.string() << "\n";
        return "Not a PE file";
    }

    // Seek to PE signature
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    if (!file) {
        if (g_verbose) std::cerr << "  [verbose] Cannot seek to PE header: " << filePath.string() << "\n";
        return "Error: bad PE offset";
    }

    // Read PE signature
    DWORD peSignature = 0;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    if (!file || peSignature != IMAGE_NT_SIGNATURE) {
        if (g_verbose) std::cerr << "  [verbose] Not a valid PE file (bad PE signature): " << filePath.string() << "\n";
        return "Not a PE file";
    }

    // Read COFF file header
    IMAGE_FILE_HEADER fileHeader{};
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    if (!file) {
        if (g_verbose) std::cerr << "  [verbose] Cannot read COFF header: " << filePath.string() << "\n";
        return "Error: truncated header";
    }

    WORD machine = fileHeader.Machine;
    std::string arch = getArchName(machine);

    if (g_verbose) {
        std::cerr << "  [verbose] " << filePath.string()
                  << " -> Machine=0x" << std::hex << machine << std::dec
                  << " (" << arch << ")\n";
    }

    // For Arm64 binaries, check the optional header for CHPE metadata which
    // distinguishes Arm64X and Arm64EC from plain Arm64.
    if (machine == IMAGE_FILE_MACHINE_ARM64) {
        // Read optional header magic to determine PE32 vs PE32+
        WORD optMagic = 0;
        auto optHeaderPos = file.tellg();
        file.read(reinterpret_cast<char*>(&optMagic), sizeof(optMagic));
        if (file && optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            // Seek back and read full optional header
            file.seekg(optHeaderPos, std::ios::beg);
            IMAGE_OPTIONAL_HEADER64 optHeader{};
            DWORD optHeaderSize = std::min<DWORD>(fileHeader.SizeOfOptionalHeader, sizeof(optHeader));
            file.read(reinterpret_cast<char*>(&optHeader), optHeaderSize);
            if (file && optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                // Check for CHPE metadata — data directory index 10 (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
                if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
                    auto& loadCfgDir = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                    if (loadCfgDir.VirtualAddress != 0 && loadCfgDir.Size > 0) {
                        // We need to find the file offset of this RVA by walking section headers
                        auto sectionTablePos = static_cast<std::streamoff>(dosHeader.e_lfanew)
                            + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
                        file.seekg(sectionTablePos, std::ios::beg);

                        DWORD loadCfgFileOffset = 0;
                        for (WORD i = 0; i < fileHeader.NumberOfSections && file; ++i) {
                            IMAGE_SECTION_HEADER sec{};
                            file.read(reinterpret_cast<char*>(&sec), sizeof(sec));
                            if (loadCfgDir.VirtualAddress >= sec.VirtualAddress &&
                                loadCfgDir.VirtualAddress < sec.VirtualAddress + sec.SizeOfRawData) {
                                loadCfgFileOffset = sec.PointerToRawData
                                    + (loadCfgDir.VirtualAddress - sec.VirtualAddress);
                                break;
                            }
                        }

                        if (loadCfgFileOffset != 0) {
                            file.seekg(loadCfgFileOffset, std::ios::beg);
                            // Read enough of the load config to reach CHPEMetadataPointer
                            // (offset 0xC0 in IMAGE_LOAD_CONFIG_DIRECTORY64)
                            constexpr size_t chpeOffset = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer);
                            constexpr size_t neededSize = chpeOffset + sizeof(ULONGLONG);
                            if (loadCfgDir.Size >= neededSize) {
                                std::vector<char> loadCfgBuf(neededSize, 0);
                                file.read(loadCfgBuf.data(), neededSize);
                                if (file) {
                                    auto pLoadCfg = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64*>(loadCfgBuf.data());
                                    if (pLoadCfg->Size >= neededSize && pLoadCfg->CHPEMetadataPointer != 0) {
                                        arch = "Arm64EC";
                                        if (g_verbose) {
                                            std::cerr << "  [verbose] CHPE metadata found -> Arm64EC\n";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return arch;
}

bool isExecutableExtension(const fs::path& ext) {
    std::string e = ext.string();
    std::transform(e.begin(), e.end(), e.begin(), ::tolower);
    return (e == ".exe" || e == ".dll");
}

int main(int argc, char* argv[]) {
    bool scanSubfolders = false;
    std::string targetPath;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.size() >= 2 && (arg[0] == '-' || arg[0] == '/')) {
            std::string flag = arg.substr(1);
            std::transform(flag.begin(), flag.end(), flag.begin(), ::tolower);
            if (flag == "s") {
                scanSubfolders = true;
            } else if (flag == "v") {
                g_verbose = true;
            } else {
                std::cerr << "Error: Unrecognised option '" << arg << "'\n\n";
                printUsage(argv[0]);
                return 1;
            }
        } else {
            if (!targetPath.empty()) {
                std::cerr << "Error: Multiple paths specified.\n\n";
                printUsage(argv[0]);
                return 1;
            }
            targetPath = arg;
        }
    }

    // Default to current directory
    fs::path basePath = targetPath.empty() ? fs::current_path() : fs::path(targetPath);

    std::error_code ec;
    basePath = fs::canonical(basePath, ec);
    if (ec || !fs::is_directory(basePath, ec)) {
        std::cerr << "Error: Path does not exist or is not a directory: " << basePath.string() << "\n\n";
        printUsage(argv[0]);
        return 1;
    }

    if (g_verbose) {
        std::cerr << "[verbose] Scanning: " << basePath.string() << "\n";
        std::cerr << "[verbose] Recursive: " << (scanSubfolders ? "yes" : "no") << "\n";
    }

    std::vector<FileResult> results;

    auto processEntry = [&](const fs::directory_entry& entry) {
        if (!entry.is_regular_file())
            return;
        if (!isExecutableExtension(entry.path().extension()))
            return;

        if (g_verbose) {
            std::cerr << "[verbose] Found: " << entry.path().string() << "\n";
        }

        std::string arch = determineArchitecture(entry.path());
        fs::path rel = fs::relative(entry.path(), basePath, ec);
        std::string relStr = rel.string();
        if (ec) relStr = entry.path().string();

        results.push_back({ relStr, arch });
    };

    if (scanSubfolders) {
        for (const auto& entry : fs::recursive_directory_iterator(basePath, fs::directory_options::skip_permission_denied, ec)) {
            processEntry(entry);
        }
    } else {
        for (const auto& entry : fs::directory_iterator(basePath, fs::directory_options::skip_permission_denied, ec)) {
            processEntry(entry);
        }
    }

    if (results.empty()) {
        std::cout << "No .exe or .dll files found.\n";
        return 0;
    }

    // Determine column widths
    size_t maxPath = 4; // "File"
    size_t maxArch = 12; // "Architecture"
    for (const auto& r : results) {
        maxPath = (std::max)(maxPath, r.relativePath.size());
        maxArch = (std::max)(maxArch, r.architecture.size());
    }

    // Print table
    std::cout << std::left
              << std::setw(static_cast<int>(maxPath + 2)) << "File"
              << "Architecture" << "\n";
    std::cout << std::string(maxPath + 2, '-') << std::string(maxArch, '-') << "\n";

    for (const auto& r : results) {
        std::cout << std::left
                  << std::setw(static_cast<int>(maxPath + 2)) << r.relativePath
                  << r.architecture << "\n";
    }

    std::cout << "\nTotal: " << results.size() << " file(s) scanned.\n";

    return 0;
}
