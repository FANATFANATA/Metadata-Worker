#include "metadata.hpp"
#include "decryptor.hpp"
#include "config.hpp"
#include "i18n.hpp"
#include "utils.hpp"
#include <iostream>
#include <string>

using namespace i18n;

void printBanner() {
    std::cout << tr("banner") << std::endl;
}

void showMenu() {
    std::cout << tr("menu_title") << std::endl;
    std::cout << tr("select_file") << std::endl;
    std::cout << tr("decrypt_file") << std::endl;
    std::cout << tr("analyze_file") << std::endl;
    std::cout << tr("exit") << std::endl;
}

int main(int argc, char* argv[]) {
    auto& cfg = config::ConfigManager::instance();
    cfg.load("config.json");
    
    setLanguage(cfg.getLanguage());
    
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Metadata Worker CLI\n";
            std::cout << "Usage: metadata-worker [options] [file]\n";
            std::cout << "Options:\n";
            std::cout << "  -h, --help     Show this help\n";
            std::cout << "  -d, --decrypt  Decrypt mode\n";
            std::cout << "  -a, --analyze  Analyze mode\n";
            std::cout << "  -l, --lang     Set language (en/ru)\n";
            return 0;
        }
        
        if (arg == "--lang" || arg == "-l") {
            if (argc > 2) {
                setLanguage(argv[2]);
            }
        }
    }
    
    printBanner();
    
    std::string currentFile;
    metadata::Decryptor decryptor;
    
    while (true) {
        showMenu();
        std::string choice = utils::promptInput(tr("choose_option"));
        
        if (choice == "0" || choice.empty()) {
            break;
        } else if (choice == "1") {
            auto& recentFiles = cfg.get().recentFiles;
            std::string path = utils::selectFileFromRecent(recentFiles);
            
            if (path.empty()) {
                path = utils::promptInput(tr("path_to_file"));
            }
            
            if (path == "q" || path.empty()) {
                continue;
            }
            
            if (!utils::fileExists(path)) {
                std::cout << tr("file_not_found") << std::endl;
                continue;
            }
            
            currentFile = path;
            cfg.addRecentFile(path);
            std::cout << "Selected: " << path << std::endl;
            
        } else if (choice == "2") {
            if (currentFile.empty()) {
                std::cout << "No file selected!" << std::endl;
                continue;
            }
            
            auto data = utils::readFile(currentFile);
            if (data.empty()) {
                std::cout << "Failed to read file!" << std::endl;
                continue;
            }
            
            if (decryptor.autoDecrypt(data)) {
                std::string outputPath = currentFile + ".decrypted";
                if (utils::writeFile(outputPath, data)) {
                    std::cout << tr("decrypt_success") << std::endl;
                    std::cout << "Saved to: " << outputPath << std::endl;
                } else {
                    std::cout << "Failed to save decrypted file!" << std::endl;
                }
            } else {
                std::cout << tr("decrypt_error") << std::endl;
            }
            
        } else if (choice == "3") {
            if (currentFile.empty()) {
                std::cout << "No file selected!" << std::endl;
                continue;
            }
            
            metadata::MetadataReader reader(currentFile);
            if (!reader.load()) {
                std::cout << tr("invalid_file") << std::endl;
                continue;
            }
            
            auto info = reader.analyze();
            
            std::cout << "\n=== File Info ===" << std::endl;
            std::cout << "Path: " << info.filePath << std::endl;
            std::cout << tr("file_size") << utils::formatFileSize(info.fileSize) << std::endl;
            std::cout << tr("encrypted") << (info.isEncrypted ? tr("yes") : tr("no")) << std::endl;
            
            if (info.unityVersion.has_value()) {
                std::cout << tr("unity_version");
                std::cout << static_cast<int>(info.unityVersion.value()) << std::endl;
            }
            
            if (!info.errorMessage.empty()) {
                std::cout << "Error: " << info.errorMessage << std::endl;
            }
        }
    }
    
    cfg.save("config.json");
    
    std::cout << "Goodbye!" << std::endl;
    return 0;
}
