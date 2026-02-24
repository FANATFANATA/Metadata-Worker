import argparse
import collections
import hashlib
import json
import logging
import os
import struct
import sys
import time
import zipfile
from datetime import datetime
from typing import Optional, Tuple, List, Callable, Any, Dict
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog

    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init
from elftools.elf.elffile import ELFFile

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

if getattr(sys, "frozen", False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)
import i18n

BANNER = i18n.get("banner")

CONFIG_FILE = os.path.join(script_dir, "config.json")
LOG_FILE = os.path.join(script_dir, "metadata-worker.log")
VERSION = "1.0.0"
GITHUB_API = "https://api.github.com/repos/user/repo/releases/latest"

colorama_init(autoreset=True)

THEMES = {
    "default": {
        "primary": Fore.CYAN,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "accent": Fore.MAGENTA,
    },
    "blue": {
        "primary": Fore.BLUE,
        "success": Fore.CYAN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "accent": Fore.WHITE,
    },
    "green": {
        "primary": Fore.GREEN,
        "success": Fore.CYAN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "accent": Fore.WHITE,
    },
    "purple": {
        "primary": Fore.MAGENTA,
        "success": Fore.CYAN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "accent": Fore.WHITE,
    },
}

DEFAULT_CONFIG = {
    "language": "en",
    "theme": "default",
    "recent_files": [],
    "last_output_dir": "",
    "check_updates": True,
}

config = DEFAULT_CONFIG.copy()
logger = None
current_theme = THEMES["default"]


def setup_logging():
    global logger
    logger = logging.getLogger("MetadataWorker")
    logger.setLevel(logging.DEBUG)
    try:
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (IOError, OSError):
        pass


def log_info(message: str):
    if logger:
        logger.info(message)


def log_error(message: str):
    if logger:
        logger.error(message)


def log_debug(message: str):
    if logger:
        logger.debug(message)


def log_warning(message: str):
    if logger:
        logger.warning(message)


def load_config():
    global config, current_theme
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved_config = json.load(f)
                config.update(saved_config)
        i18n.set_language(config.get("language", "en"))
        theme_name = config.get("theme", "default")
        current_theme = THEMES.get(theme_name, THEMES["default"])
    except (json.JSONDecodeError, IOError):
        pass


def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except (IOError, OSError) as e:
        log_error(f"Failed to save config: {e}")


def add_recent_file(path: str):
    recent = config.get("recent_files", [])
    if path in recent:
        recent.remove(path)
    recent.insert(0, path)
    config["recent_files"] = recent[:10]
    save_config()


def check_for_updates():
    if not config.get("check_updates", True) or not REQUESTS_AVAILABLE:
        return
    try:
        response = requests.get(GITHUB_API, timeout=5)
        if response.status_code == 200:
            data = response.json()
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != VERSION:
                print(
                    f"{current_theme['warning']}New version available: {latest} (current: {VERSION}){Style.RESET_ALL}"
                )
                log_info(f"Update available: {latest}")
    except Exception:
        pass


def validate_path(path: str, must_exist: bool = True) -> Optional[str]:
    try:
        if not path or not path.strip():
            return None
        p = Path(path).resolve()
        if must_exist and not p.exists():
            log_error(f"Path does not exist: {path}")
            return None
        if not must_exist:
            parent = p.parent
            if not parent.exists():
                log_error(f"Parent directory does not exist: {parent}")
                return None
        log_debug(f"Validated path: {p}")
        return str(p)
    except (ValueError, OSError) as e:
        log_error(f"Path validation error: {e}")
        return None


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def select_file_cli(title: str) -> str:
    print(f"{current_theme['primary']}{title}{Style.RESET_ALL}")
    recent = config.get("recent_files", [])
    if recent:
        print(f"{current_theme['primary']}Recent files:{Style.RESET_ALL}")
        for i, path in enumerate(recent[:5], 1):
            print(f"  [{i}] {path}")
    while True:
        try:
            path = input(i18n.get("path_to_file")).strip()
        except EOFError:
            return ""
        if path.lower() == "q":
            return ""
        if path.isdigit() and 1 <= int(path) <= len(recent):
            path = recent[int(path) - 1]
        if os.path.isfile(path):
            add_recent_file(path)
            return path
        print(f"{current_theme['error']}{i18n.get('file_not_found')}{Style.RESET_ALL}")


def select_save_file_cli(title: str, defaultextension: str = "") -> str:
    print(f"{current_theme['primary']}{title}{Style.RESET_ALL}")
    while True:
        try:
            path = input(i18n.get("path_to_save")).strip()
        except EOFError:
            return ""
        if path.lower() == "q":
            return ""
        if path:
            if defaultextension and not path.endswith(defaultextension):
                path += defaultextension
            return path
        print(f"{current_theme['error']}{i18n.get('enter_path')}{Style.RESET_ALL}")


def select_folder_cli(title: str) -> str:
    print(f"{current_theme['primary']}{title}{Style.RESET_ALL}")
    while True:
        try:
            path = input(i18n.get("path_to_folder")).strip()
        except EOFError:
            return ""
        if path.lower() == "q":
            return ""
        if os.path.isdir(path):
            return path
        print(f"{current_theme['error']}{i18n.get('folder_not_found')}{Style.RESET_ALL}")


def select_file(title: str, filetypes: list) -> str:
    if TKINTER_AVAILABLE:
        root = None
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
            if file_path:
                add_recent_file(file_path)
            return file_path
        except tk.TclError:
            pass
        finally:
            if root:
                root.destroy()
    return select_file_cli(title)


def select_save_file(title: str, filetypes: list, defaultextension: str = "") -> str:
    if TKINTER_AVAILABLE:
        root = None
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            file_path = filedialog.asksaveasfilename(
                title=title, filetypes=filetypes, defaultextension=defaultextension
            )
            return file_path
        except tk.TclError:
            pass
        finally:
            if root:
                root.destroy()
    return select_save_file_cli(title, defaultextension)


def select_folder(title: str) -> str:
    if TKINTER_AVAILABLE:
        root = None
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            folder_path = filedialog.askdirectory(title=title)
            return folder_path
        except tk.TclError:
            pass
        finally:
            if root:
                root.destroy()
    return select_folder_cli(title)


def loading_animation():
    frames = ["|", "/", "-", "\\"]
    for frame in frames:
        print(f"Running...{frame}", end="\r")
        time.sleep(0.1)
    print(" " * 20, end="\r")


def is_valid_metadata(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return data[:4] == METADATA_MAGIC


def get_metadata_version(data: bytes) -> Tuple[int, str]:
    if len(data) < 8:
        return -1, "Unknown"
    version = struct.unpack("<I", data[4:8])[0]
    desc = SUPPORTED_VERSIONS.get(version, f"Unknown (v{version})")
    return version, desc


def decrypt_xor(data: bytes, key: List[int]) -> bytes:
    result = bytearray(len(data))
    klen = len(key)
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % klen]
    return bytes(result)


def decrypt_xxtea(data: bytes, key: bytes) -> bytes:
    if len(key) < 4:
        return data
    sum_val, delta = 0x00000000, 0x9E3779B9
    if len(data) % 4 != 0 or len(data) // 4 < 2:
        return data
    out = bytearray(data)
    key_idx = len(key) // 4
    if key_idx < 1:
        return data
    for i in range(0, len(out), 8):
        if i + 8 > len(out):
            break
        v = list(struct.unpack_from("<II", out, i))
        sum_val = (delta * 32) & 0xFFFFFFFF
        for _ in range(32):
            v[1] = (
                v[1]
                - (
                    ((v[0] << 4) + v[0])
                    ^ (v[0] + sum_val)
                    ^ ((v[0] >> 5) + key[(sum_val >> 11) & (key_idx - 1)])
                )
            ) & 0xFFFFFFFF
            v[0] = (
                v[0]
                - (
                    ((v[1] << 4) + v[1])
                    ^ (v[1] + sum_val)
                    ^ ((v[1] >> 5) + key[sum_val & (key_idx - 1)])
                )
            ) & 0xFFFFFFFF
            sum_val = (sum_val - delta) & 0xFFFFFFFF
        struct.pack_into("<II", out, i, v[0], v[1])
    return bytes(out)


def decrypt_rc4(data: bytes, key: bytes = b"wanzg") -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[n] = data[n] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)


def auto_find_xor_key(data: bytes) -> Optional[List[int]]:
    if len(data) < 0x120:
        return None
    target = b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
    for klen in range(3, 13):
        for i in range(0x100, 0x118):
            if i + len(target) > len(data):
                continue
            key = [data[i + j] ^ target[j] for j in range(len(target))]
            valid = True
            for j in range(klen):
                if key[j] != key[j % klen]:
                    valid = False
                    break
            if valid:
                return list(dict.fromkeys(key))[:klen]
    return None


def auto_header_xor_key(data: bytes) -> Optional[List[int]]:
    if len(data) < 8:
        return None
    expected_magic = METADATA_MAGIC
    key = [data[i] ^ expected_magic[i] for i in range(4)]
    if all(k != 0 for k in key):
        test_decrypt = decrypt_xor(data[:16], key)
        if test_decrypt[:4] == METADATA_MAGIC:
            return key
    return None


def auto_wanzg_key(data: bytes) -> Optional[List[int]]:
    if len(data) < 0x120:
        return None
    target = b"\x00" * 8 + b"\x01\x00\x00\x00"
    for i in range(0x100, 0x118):
        if i + 12 > len(data):
            continue
        k = [data[i + j] ^ target[j] for j in range(12)]
        if k[0] == k[4] and k[1] == k[5] and k[2] == k[6]:
            return k[:5]
    return None


def decrypt_striped_xor(data: bytes, key: int = 0xA3, stripe: int = 0x1000) -> bytes:
    out = bytearray(data)
    for i in range(0, len(out), stripe * 2):
        for j in range(min(stripe, len(out) - i)):
            out[i + j] ^= key
    return bytes(out)


def try_decrypt_metadata(data: bytes) -> Tuple[bytes, Optional[str]]:
    if is_valid_metadata(data):
        return data, None
    key = auto_header_xor_key(data)
    if key:
        decrypted = decrypt_xor(data, key)
        if is_valid_metadata(decrypted):
            return decrypted, f"HEADER-XOR:{key}"
    key = auto_wanzg_key(data)
    if key:
        decrypted = decrypt_xor(data, key)
        if is_valid_metadata(decrypted):
            return decrypted, f"WANZG:{key}"
    key = auto_find_xor_key(data)
    if key:
        decrypted = decrypt_xor(data, key)
        if is_valid_metadata(decrypted):
            return decrypted, f"AUTO-XOR:{key}"
    decrypted = decrypt_striped_xor(data)
    if is_valid_metadata(decrypted):
        return decrypted, "STRIPED-XOR-0xA3"
    decrypted = decrypt_striped_xor(data, 0x53)
    if is_valid_metadata(decrypted):
        return decrypted, "STRIPED-XOR-0x53"
    for key in COMMON_XOR_KEYS:
        decrypted = decrypt_xor(data, key)
        if is_valid_metadata(decrypted):
            return decrypted, f"XOR:{key}"
    for key_len in [4, 8, 16, 32]:
        test_key = list(data[:key_len])
        decrypted = decrypt_xor(data, test_key)
        if is_valid_metadata(decrypted):
            return decrypted, f"XOR:{test_key}"
    decrypted = decrypt_rc4(data)
    if is_valid_metadata(decrypted):
        return decrypted, "RC4"
    for rc4_key in [b"NEP2", b"Tarkov", b"wanzg"]:
        decrypted = decrypt_rc4(data, rc4_key)
        if is_valid_metadata(decrypted):
            return decrypted, f"RC4-{rc4_key.decode()}"
    for key in [b"\x00" * 16, b"\xff" * 16, b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 2]:
        decrypted = decrypt_xxtea(data, key)
        if is_valid_metadata(decrypted):
            return decrypted, f"XXTEA:{key.hex()}"
    return data, None


def find_metadata_in_libunity(libunity_path: str) -> Optional[int]:
    with open(libunity_path, "rb") as f:
        data = f.read()
    idx = data.find(METADATA_MAGIC)
    if idx != -1:
        print(
            f"{current_theme['success']}Found embedded metadata at offset {hex(idx)}{Style.RESET_ALL}"
        )
        log_info(f"Found metadata in libunity at offset {hex(idx)}")
        return idx
    return None


def find_metadata_in_apk(apk_path: str) -> Optional[Tuple[str, int]]:
    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            for name in apk.namelist():
                if "metadata" in name.lower() and name.endswith(".dat"):
                    info = apk.getinfo(name)
                    print(
                        f"{current_theme['success']}Found metadata in APK: {name} ({info.file_size} bytes){Style.RESET_ALL}"
                    )
                    log_info(f"Found metadata in APK: {name}")
                    return name, info.file_size
    except zipfile.BadZipFile:
        print(f"{current_theme['error']}Error: Invalid APK file{Style.RESET_ALL}")
        log_error("Invalid APK file")
    except (IOError, OSError) as e:
        print(f"{current_theme['error']}Error reading APK: {e}{Style.RESET_ALL}")
        log_error(f"Error reading APK: {e}")
    return None


def find_metadata_in_folder(folder_path: str) -> Optional[Tuple[str, int]]:
    metadata_paths = [
        os.path.join(
            folder_path,
            "assets",
            "bin",
            "Data",
            "Managed",
            "Metadata",
            "global-metadata.dat",
        ),
        os.path.join(
            folder_path, "assets", "bin", "Data", "Managed", "global-metadata.dat"
        ),
        os.path.join(
            folder_path, "assets", "il2cpp_data", "Metadata", "global-metadata.dat"
        ),
        os.path.join(folder_path, "assets", "global-metadata.dat"),
        os.path.join(folder_path, "global-metadata.dat"),
    ]
    for path in metadata_paths:
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                print(
                    f"{current_theme['success']}Found metadata in folder: {path} ({size} bytes){Style.RESET_ALL}"
                )
                log_info(f"Found metadata: {path}")
                return path, size
            except (IOError, OSError):
                continue
    for depth, (root, dirs, files) in enumerate(os.walk(folder_path)):
        if depth > 5:
            break
        for file in files:
            if "metadata" in file.lower() and file.endswith(".dat"):
                path = os.path.join(root, file)
                try:
                    size = os.path.getsize(path)
                    print(
                        f"{current_theme['success']}Found metadata: {path} ({size} bytes){Style.RESET_ALL}"
                    )
                    log_info(f"Found metadata: {path}")
                    return path, size
                except (IOError, OSError):
                    continue
    return None


def extract_from_apk(input_path: str, output_path: str, force: bool = False) -> bool:
    log_info(f"Extracting from APK: {input_path} -> {output_path}")
    try:
        is_folder = os.path.isdir(input_path)
        is_apk = os.path.isfile(input_path) and input_path.lower().endswith(".apk")
        if not is_folder and not is_apk:
            print(
                f"{current_theme['error']}Error: {input_path} is not a valid APK file or folder{Style.RESET_ALL}"
            )
            log_error(f"Invalid input: {input_path}")
            return False
        data = None
        if is_apk:
            result = find_metadata_in_apk(input_path)
            if not result:
                print(f"{current_theme['warning']}No metadata found in APK{Style.RESET_ALL}")
                log_warning("No metadata in APK")
                return False
            try:
                with zipfile.ZipFile(input_path, "r") as apk:
                    data = apk.read(result[0])
            except zipfile.BadZipFile:
                print(f"{current_theme['error']}Error: Invalid APK file{Style.RESET_ALL}")
                log_error("Invalid APK")
                return False
        else:
            result = find_metadata_in_folder(input_path)
            if not result:
                print(f"{current_theme['warning']}No metadata found in folder{Style.RESET_ALL}")
                log_warning("No metadata in folder")
                return False
            with open(result[0], "rb") as f:
                data = f.read()
        data, key = try_decrypt_metadata(data)
        if key:
            print(f"{current_theme['success']}Auto-decrypted: {key}{Style.RESET_ALL}")
            log_info(f"Auto-decrypted: {key}")
        elif not force and data[:4] != METADATA_MAGIC:
            print(
                f"{current_theme['warning']}Metadata appears encrypted. Use --force to extract anyway.{Style.RESET_ALL}"
            )
            version, desc = get_metadata_version(data)
            print(f"{current_theme['primary']}Version detected: {version} ({desc}){Style.RESET_ALL}")
            return False
        with open(output_path, "wb") as f:
            f.write(data)
        print(f"{current_theme['success']}Metadata extracted to {output_path}{Style.RESET_ALL}")
        log_info(f"Extracted to {output_path}")
        return True
    except (IOError, OSError, zipfile.BadZipFile) as e:
        print(f"{current_theme['error']}Error extracting from APK: {e}{Style.RESET_ALL}")
        log_error(f"Extract error: {e}")
        return False


def map_vaddr_to_offset(va: int, load_segments: List[Tuple[int, int, int]]) -> int:
    for start, end, offset in load_segments:
        if start <= va < end:
            return va - start + offset
    raise ValueError(f"Virtual address {hex(va)} not found in LOAD segments")


def extract_metadata_pointer(libunity_path: str) -> Optional[int]:
    try:
        with open(libunity_path, "rb") as libunity:
            elf = ELFFile(libunity)
            is64bit = elf.get_machine_arch() == "AArch64"
            load_segments = [
                (seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"], seg["p_offset"])
                for seg in elf.iter_segments()
                if seg["p_type"] == "PT_LOAD"
            ]
            data_section = elf.get_section_by_name(".data")
            if not data_section:
                print(f"{current_theme['error']}Error: .data section not found.{Style.RESET_ALL}")
                log_error(".data section not found")
                return None
            print(f"{current_theme['primary']}Collecting relocations...{Style.RESET_ALL}")
            log_debug("Collecting relocations")
            relocations = []
            for section in elf.iter_sections():
                if section.header["sh_type"] not in ("SHT_REL", "SHT_RELA"):
                    continue
                total = section.header["sh_size"] // (24 if is64bit else 8)
                for relocation in tqdm(
                    section.iter_relocations(),
                    colour="green",
                    unit="rel",
                    total=total,
                    leave=False,
                ):
                    addr = relocation["r_offset"]
                    if not (
                        data_section["sh_addr"]
                        <= addr
                        < data_section["sh_addr"] + data_section["sh_size"]
                    ):
                        continue
                    if is64bit:
                        pointer = relocation.get("r_addend", 0)
                        if pointer != 0:
                            relocations.append(pointer)
                    else:
                        try:
                            offset = map_vaddr_to_offset(addr, load_segments)
                        except ValueError:
                            continue
                        libunity.seek(offset)
                        pointer = struct.unpack("<I", libunity.read(4))[0]
                        if pointer != 0:
                            relocations.append(pointer)
            print(f"{current_theme['primary']}Searching for metadata pointer...{Style.RESET_ALL}")
            candidates = []
            for addr in tqdm(relocations, colour="green", unit="rel", leave=False):
                try:
                    libunity.seek(addr - 16)
                    data = libunity.read(16)
                    if data == METADATA_SIGNATURE:
                        candidates.append(addr)
                except Exception:
                    continue
            if not candidates:
                print(
                    f"{current_theme['warning']}Warning: No metadata pointer found via relocations, trying alternative method...{Style.RESET_ALL}"
                )
                return extract_metadata_pointer_alternative(libunity_path)
            elif len(candidates) > 1:
                print(
                    f"{current_theme['warning']}Multiple candidates found, using first: {hex(candidates[0])}{Style.RESET_ALL}"
                )
            return candidates[0]
    except Exception as e:
        print(f"{current_theme['error']}Error extracting metadata pointer: {e}{Style.RESET_ALL}")
        log_error(f"Pointer extraction error: {e}")
        return None


def extract_metadata_pointer_alternative(libunity_path: str) -> Optional[int]:
    try:
        with open(libunity_path, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(f"{current_theme['error']}Error reading libunity.so: {e}{Style.RESET_ALL}")
        log_error(f"Read error: {e}")
        return None
    print(f"{current_theme['primary']}Scanning for metadata magic bytes...{Style.RESET_ALL}")
    idx = data.find(METADATA_MAGIC)
    if idx != -1:
        print(f"{current_theme['success']}Found metadata at offset: {hex(idx)}{Style.RESET_ALL}")
        return idx
    print(f"{current_theme['primary']}Scanning for metadata signature...{Style.RESET_ALL}")
    idx = data.find(METADATA_SIGNATURE)
    if idx != -1:
        print(
            f"{current_theme['success']}Found metadata signature at offset: {hex(idx)}{Style.RESET_ALL}"
        )
        return idx
    print(f"{current_theme['error']}Error: No metadata found in libunity.so{Style.RESET_ALL}")
    return None


def extract_metadata(
    libunity_path: str, size: int = 30_000_000
) -> Optional[Tuple[bytes, bool]]:
    log_info(f"Extracting metadata from: {libunity_path}")
    try:
        embedded_offset = find_metadata_in_libunity(libunity_path)
        if embedded_offset is not None:
            with open(libunity_path, "rb") as f:
                f.seek(embedded_offset)
                metadata = f.read(size)
            metadata, key = try_decrypt_metadata(metadata)
            if key:
                print(f"{current_theme['success']}Auto-decrypted: {key}{Style.RESET_ALL}")
            version, desc = get_metadata_version(metadata)
            print(f"{current_theme['primary']}Metadata version: {version} ({desc}){Style.RESET_ALL}")
            return metadata, True
        metadata_ptr = extract_metadata_pointer(libunity_path)
        if metadata_ptr is None:
            return None
        with open(libunity_path, "rb") as libunity:
            libunity.seek(metadata_ptr)
            metadata = libunity.read(size)
        metadata, key = try_decrypt_metadata(metadata)
        if key:
            print(f"{current_theme['success']}Auto-decrypted: {key}{Style.RESET_ALL}")
        is64bit = True
        index = metadata.find(METADATA_MARKER_64)
        if index == -1:
            index = metadata.find(METADATA_MARKER_32)
            is64bit = False
        if index != -1:
            index += (4 - index % 4) % 4
            if index > 0 and index <= len(metadata):
                metadata = metadata[:index]
            print(
                f"{current_theme['success']}Metadata end marker found ({'64-bit' if is64bit else '32-bit'}).{Style.RESET_ALL}"
            )
        else:
            print(
                f"{current_theme['error']}Warning: End marker not found, using full dump.{Style.RESET_ALL}"
            )
        version, desc = get_metadata_version(metadata)
        print(f"{current_theme['primary']}Metadata version: {version} ({desc}){Style.RESET_ALL}")
        print(f"{current_theme['primary']}Metadata size: {len(metadata)} bytes{Style.RESET_ALL}")
        return metadata, is64bit
    except (IOError, OSError, struct.error) as e:
        print(f"{current_theme['error']}Error extracting metadata: {e}{Style.RESET_ALL}")
        log_error(f"Extract error: {e}")
        return None


def find_offset_candidates(metadata: bytes) -> List[int]:
    fields = []
    for i in range(0, 256, 4):
        value = struct.unpack("<I", metadata[i : i + 4])[0]
        if 0 < value < len(metadata):
            fields.append(value)
    candidates = []
    for field in fields:
        if field < 8192 or field % 4 != 0:
            if field == 256:
                candidates.append(field)
            continue
        if field > len(metadata) / 3:
            candidates.append(field)
            continue
        behind = metadata[field - 4096 : field]
        ahead = metadata[field : field + 4096]
        zeroes_behind = behind.count(b"\0")
        zeroes_ahead = ahead.count(b"\0")
        counter_behind = collections.Counter(behind)
        counter_ahead = collections.Counter(ahead)
        keys = set(counter_behind.keys()) | set(counter_ahead.keys())
        freq_behind = {k: counter_behind.get(k, 0) / 4096 for k in keys}
        freq_ahead = {k: counter_ahead.get(k, 0) / 4096 for k in keys}
        dist = sum(abs(freq_behind[k] - freq_ahead[k]) for k in keys)
        score = abs(zeroes_behind - zeroes_ahead) / 512 + dist
        if score > 0.75:
            candidates.append(field)
    return sorted(set(candidates))


def apply_heuristic(
    name: str,
    offsets_to_sizes: List[Tuple[int, int]],
    metadata: bytes,
    callback: Optional[Callable[[List[Any]], bool]],
    struct_sig: Optional[str],
    prefer_lowest: bool,
    marker: Optional[bytes],
) -> Tuple[Optional[Tuple[int, int, bytes]], List[Tuple[int, int]]]:
    found = []
    remaining = offsets_to_sizes.copy()
    for offset, size in tqdm(
        offsets_to_sizes, desc=f"Scanning {name}", colour="green", leave=False
    ):
        data = metadata[offset : offset + size]
        if marker and marker in data:
            found.append((offset, size, data))
            break
        if not struct_sig:
            continue
        step = struct.calcsize(struct_sig)
        entries = []
        for i in range(0, len(data), step):
            try:
                fields = struct.unpack_from(struct_sig, data, i)
                entries.append(
                    fields[0] if len(struct_sig.rstrip("x")) <= 1 else fields
                )
            except struct.error:
                break
        if callback and callback(entries):
            found.append((offset, size, data))
    if not found:
        print(f"{current_theme['error'] + Style.BRIGHT}Failed heuristic: {name}{Style.RESET_ALL}")
        return None, offsets_to_sizes
    found.sort(key=lambda x: x[1], reverse=not prefer_lowest)
    result = found[0]
    if result[:2] in remaining:
        remaining.remove(result[:2])
    print(f"{current_theme['primary']}Found {name} at offset {result[0]}{Style.RESET_ALL}")
    log_debug(f"Found {name} at {result[0]}")
    return result, remaining


def decrypt_metadata(
    metadata: bytes, output_path: str, exclude_offsets: Optional[str] = None
) -> bool:
    log_info(f"Decrypting metadata to: {output_path}")
    try:
        print(f"{current_theme['success']}Starting metadata decryption...{Style.RESET_ALL}")
        metadata, key = try_decrypt_metadata(metadata)
        if key:
            print(f"{current_theme['success']}Auto-decrypted: {key}{Style.RESET_ALL}")
        else:
            print(
                f"{current_theme['primary']}Metadata is not encrypted or uses unknown encryption{Style.RESET_ALL}"
            )
        version, desc = get_metadata_version(metadata)
        print(f"{current_theme['primary']}Metadata version: {version} ({desc}){Style.RESET_ALL}")
        if version < 15 or version > 43:
            print(
                f"{current_theme['warning']}Warning: Unknown metadata version {version}{Style.RESET_ALL}"
            )
        elif version > 38:
            print(
                f"{current_theme['warning']}Warning: Version {version} may have limited support{Style.RESET_ALL}"
            )
        debug_path = os.path.join(script_dir, "debug-metadata.bin")
        with open(debug_path, "wb") as f:
            f.write(metadata)
        print(f"{current_theme['primary']}Debug dump saved to {debug_path}{Style.RESET_ALL}")
        offset_candidates = find_offset_candidates(metadata)
        print(
            f"{current_theme['primary']}Found {len(offset_candidates)} offset candidates{Style.RESET_ALL}"
        )
        if exclude_offsets:
            for excluded in exclude_offsets.split(","):
                try:
                    todelete = int(excluded)
                    offset_candidates.remove(todelete)
                    print(f"{current_theme['primary']}Excluded offset {todelete}{Style.RESET_ALL}")
                except (ValueError, KeyError):
                    print(
                        f"{current_theme['warning']}Offset {todelete} not found in candidates{Style.RESET_ALL}"
                    )
        offsets_to_sizes: List[Tuple[int, int]] = []
        only_sizes = [
            x
            for x in [
                struct.unpack("<I", metadata[i : i + 4])[0] for i in range(0, 256, 4)
            ]
            if x not in offset_candidates
        ]
        for offset in offset_candidates:
            search_pool = (
                only_sizes
                if offset != 256
                else [
                    struct.unpack("<I", metadata[i : i + 4])[0]
                    for i in range(0, 256, 4)
                ]
            )
            for size in search_pool:
                if size != offset and size != 0 and size < len(metadata) / 3:
                    if offset + size == len(metadata):
                        offsets_to_sizes.append((offset, size))
                        break
                    for next_off in offset_candidates:
                        if offset + size == next_off:
                            offsets_to_sizes.append((offset, size))
                            break
        offsets_to_sizes = sorted(offsets_to_sizes, key=lambda x: x[0])
        print(
            f"{current_theme['primary']}Validated {len(offsets_to_sizes)} offset/size pairs{Style.RESET_ALL}"
        )
        reconstructed = bytearray(METADATA_HEADER_MAGIC + b"\x00" * 244)
        reconstructed_offsets = []

        def string_literal_cb(e):
            return (
                all(
                    e[i][1] == (e[0][1] + sum(x[0] for x in e[:i]))
                    for i in range(1, len(e))
                )
                if e
                else True
            )

        def events_cb(e):
            return (
                all(
                    e[i][0] >= e[i - 1][0] and e[i][2] < 1024 and e[i][3] < 1024
                    for i in range(1, len(e))
                )
                if e
                else True
            )

        def token_cb(prefix):
            return lambda e: (
                all((x[-1] & 0xFF000000) == prefix for x in e if len(x) > 0)
                if e
                else True
            )

        def ascending_cb(e):
            return all(e[i][0] <= e[i + 1][0] for i in range(len(e) - 1)) if e else True

        heuristics = [
            ("stringLiteral", string_literal_cb, "<II", True, None),
            (
                "stringLiteralData",
                None,
                None,
                True,
                b"\x00\x00\x00\x00\x01\x09\x00\x00\x01",
            ),
            ("string", None, None, True, b"Assembly-CSharp\x00\x00\x00\x00\x00Assembl"),
            ("events", events_cb, "<IIIIII", False, None),
            ("properties", token_cb(0x17000000), "<IIIII", False, None),
            ("methods", token_cb(0x06000000), "<IIIIIIIHHHHxx", False, None),
            ("parameterDefaultValues", ascending_cb, "<III", True, None),
            ("fieldDefaultValues", ascending_cb, "<III", False, None),
            (
                "fieldAndParameterDefaultValuesData",
                None,
                None,
                False,
                b"\\Assets\\ThirdParty\\I2\\Localization",
            ),
            ("fieldMarshaledSizes", ascending_cb, "<III", True, None),
            ("parameters", token_cb(0x08000000), "<III", True, None),
            ("fields", token_cb(0x04000000), "<III", True, None),
            ("genericParameters", None, "<IIHHHHxx", True, None),
            ("genericParameterContraints", None, "<I", True, None),
            ("genericContainers", None, "<IIII", False, None),
            ("nestedTypes", None, "<I", False, None),
            ("interfaces", None, "<I", False, None),
            ("vtableMethods", None, "<I", False, None),
            ("interfaceOffsets", None, "<II", False, None),
            ("typeDefinitions", None, "<IIIIIIIIIIIIIIIIHHHHHHHHxxII", False, None),
            ("images", None, "<IIIIIIIIII", False, None),
            ("assemblies", token_cb(0x20000000), "<IIIIIIIIIIIIIIII", False, None),
            ("fieldRefs", None, "<II", False, None),
            ("referencedAssemblies", None, "<I", False, None),
            ("attributeData", None, None, False, b"NewFragmentBox"),
            ("attributeDataRange", None, "<II", False, None),
            ("unresolvedIndirectCallParameterTypes", None, "<I", False, None),
            ("unresolvedIndirectCallParameterTypeRanges", None, "<II", False, None),
            ("exportedTypeDefinitions", None, "<I", False, None),
        ]
        for h_name, h_cb, h_sig, h_pref, h_marker in tqdm(
            heuristics, desc="Applying heuristics", colour="green"
        ):
            result, offsets_to_sizes = apply_heuristic(
                h_name, offsets_to_sizes, metadata, h_cb, h_sig, h_pref, h_marker
            )
            if result:
                reconstructed_offsets.append(result[0])
        if len(reconstructed_offsets) < 28:
            print(
                f"{current_theme['warning']}Warning: Only found {len(reconstructed_offsets)} sections (expected 29){Style.RESET_ALL}"
            )
        pos = 0

        def add_header_size(size):
            nonlocal pos
            if len(reconstructed) >= 20 + pos:
                reconstructed[12 + pos : 16 + pos] = struct.pack("<I", size)
                new_total = (
                    struct.unpack("<I", reconstructed[8 + pos : 12 + pos])[0] + size
                )
                reconstructed[16 + pos : 20 + pos] = struct.pack("<I", new_total)
                pos += 8

        offset_lookup = sorted(reconstructed_offsets)
        for i in range(28):
            if i < len(reconstructed_offsets):
                offset = reconstructed_offsets[i]
                try:
                    idx = offset_lookup.index(offset)
                    size = (
                        offset_lookup[idx + 1] - offset
                        if idx + 1 < len(offset_lookup)
                        else len(metadata) - offset
                    )
                except (ValueError, IndexError):
                    size = len(metadata) - offset
                add_header_size(size)
                reconstructed += metadata[offset : offset + size]
        if len(reconstructed) >= 256:
            reconstructed[252:256] = struct.pack(
                "<I", len(metadata) - struct.unpack("<I", reconstructed[248:252])[0]
            )
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, "output-metadata.dat")
        with open(output_path, "wb") as f:
            f.write(reconstructed)
        print(f"{current_theme['accent'] + Style.BRIGHT}Output: {output_path}{Style.RESET_ALL}")
        print(f"{current_theme['success']}Metadata decrypted successfully!{Style.RESET_ALL}")
        log_info(f"Decrypted to {output_path}")
        return True
    except (IOError, OSError, struct.error) as e:
        print(f"{current_theme['error']}Error decrypting metadata: {e}{Style.RESET_ALL}")
        log_error(f"Decrypt error: {e}")
        return False


def print_menu():
    print()
    print(f"{current_theme['primary']}╔{'═'*62}╗{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['success']}1{Style.RESET_ALL}. {i18n.get('menu_extract'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['success']}2{Style.RESET_ALL}. {i18n.get('menu_decrypt'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['success']}3{Style.RESET_ALL}. {i18n.get('menu_info'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['success']}4{Style.RESET_ALL}. {i18n.get('menu_apk'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['warning']}5{Style.RESET_ALL}. {i18n.get('menu_switch_lang'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['warning']}6{Style.RESET_ALL}. {i18n.get('menu_theme'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {current_theme['error']}0{Style.RESET_ALL}. {i18n.get('menu_exit'):<57}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}╚{'═'*62}╝{Style.RESET_ALL}")


def menu_extract():
    clear_screen()
    print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {i18n.get('extract_title'):^52}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
    libunity = select_file(
        i18n.get("select_libunity"), [("SO files", ".so"), ("All files", ".*")]
    )
    if not libunity:
        print(f"{current_theme['error']}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('libunity')}{libunity}")
    output = select_save_file(
        i18n.get("save_metadata"), [("DAT files", ".dat"), ("All files", ".*")], ".dat"
    )
    if not output:
        print(f"{current_theme['error']}{i18n.get('no_output_path')}{Style.RESET_ALL}")
        return
    try:
        size = input(i18n.get("max_size")).strip()
        size = int(size) if size else 30_000_000
    except (EOFError, ValueError):
        size = 30_000_000
    result = extract_metadata(libunity, size)
    if result:
        metadata, _ = result
        with open(output, "wb") as f:
            f.write(metadata)
        print(f"{current_theme['success']}{i18n.get('extracted_to')}{output}{Style.RESET_ALL}")


def menu_decrypt():
    clear_screen()
    print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {i18n.get('decrypt_title'):^52}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
    input_file = select_file(
        i18n.get("select_encrypted"), [("DAT files", ".dat"), ("All files", ".*")]
    )
    if not input_file:
        print(f"{current_theme['error']}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('input')}{input_file}")
    output = select_save_file(
        i18n.get("save_decrypted"), [("DAT files", ".dat"), ("All files", ".*")], ".dat"
    )
    if not output:
        print(f"{current_theme['error']}{i18n.get('no_output_path')}{Style.RESET_ALL}")
        return
    try:
        exclude = input("Exclude offsets (e.g., 1,2,3 or empty): ").strip() or None
        with open(input_file, "rb") as f:
            metadata = f.read()
        decrypt_metadata(metadata, output, exclude)
    except Exception as e:
        print(f"{current_theme['error']}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_info():
    clear_screen()
    print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {i18n.get('info_title'):^52}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
    input_file = select_file(
        i18n.get("select_metadata"), [("DAT files", ".dat"), ("All files", ".*")]
    )
    if not input_file:
        print(f"{current_theme['error']}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('file')}{input_file}")
    try:
        with open(input_file, "rb") as f:
            data = f.read(512)
        print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
        print(f"{current_theme['primary']}║{Style.RESET_ALL}  {i18n.get('metadata_info_title'):^52}{current_theme['primary']}║{Style.RESET_ALL}")
        print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
        print(f"{i18n.get('magic')}{data[:4].hex().upper()}")
        version, desc = get_metadata_version(data)
        print(f"{i18n.get('version')}{version} ({desc})")
        print(f"{i18n.get('file_size')}{os.path.getsize(input_file)} bytes")
        if data[:4] != METADATA_MAGIC:
            print(f"{current_theme['warning']}{i18n.get('warning_invalid_magic')}{Style.RESET_ALL}")
        decrypted, key = try_decrypt_metadata(data)
        if key:
            print(
                f"{current_theme['success']}{i18n.get('possible_encryption')}{key}{Style.RESET_ALL}"
            )
    except Exception as e:
        print(f"{current_theme['error']}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_apk():
    clear_screen()
    print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {i18n.get('apk_title'):^52}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
    print(f"{current_theme['warning']}{i18n.get('apk_select')}{Style.RESET_ALL}")
    input_path = select_file(
        i18n.get("select_apk"), [("APK files", ".apk"), ("All files", ".*")]
    )
    if not input_path:
        print(f"{current_theme['error']}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    if os.path.isdir(input_path):
        print(f"{i18n.get('folder')}{input_path}")
    else:
        print(f"{i18n.get('apk')}{input_path}")
    output = select_save_file(
        i18n.get("save_metadata"), [("DAT files", ".dat"), ("All files", ".*")], ".dat"
    )
    if not output:
        print(f"{current_theme['error']}{i18n.get('no_output_path')}{Style.RESET_ALL}")
        return
    try:
        force = input(i18n.get("force_extract")).strip().lower() == "y"
    except EOFError:
        force = False
    try:
        extract_from_apk(input_path, output, force)
    except Exception as e:
        print(f"{current_theme['error']}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_theme():
    global current_theme
    clear_screen()
    print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
    print(f"{current_theme['primary']}║{Style.RESET_ALL}  {'Select Theme':^52}{current_theme['primary']}║{Style.RESET_ALL}")
    print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
    print()
    themes = list(THEMES.keys())
    for i, name in enumerate(themes, 1):
        print(f"  {i}. {name.capitalize()}")
    print(f"  0. Cancel")
    try:
        choice = input(f"\n{current_theme['primary']}Select: {Style.RESET_ALL}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(themes):
            theme_name = themes[int(choice) - 1]
            config["theme"] = theme_name
            current_theme = THEMES[theme_name]
            save_config()
            print(f"{current_theme['success']}Theme changed to {theme_name}{Style.RESET_ALL}")
    except (EOFError, ValueError):
        pass


def interactive_menu():
    clear_screen()
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    loading_animation()
    check_for_updates()
    while True:
        print_menu()
        try:
            choice = input(
                f"{current_theme['primary']}{i18n.get('select_option')}{Style.RESET_ALL}: "
            ).strip()
        except EOFError:
            print(f"\n{current_theme['success']}{i18n.get('exiting')}{Style.RESET_ALL}")
            break
        if choice == "1":
            menu_extract()
        elif choice == "2":
            menu_decrypt()
        elif choice == "3":
            menu_info()
        elif choice == "4":
            menu_apk()
        elif choice == "5":
            lang = i18n.toggle_language()
            config["language"] = lang
            save_config()
            print(
                f"{current_theme['success']}{i18n.get('lang_changed')}{lang.upper()}{Style.RESET_ALL}"
            )
        elif choice == "6":
            menu_theme()
        elif choice == "0":
            print(f"{current_theme['success']}{i18n.get('exiting')}{Style.RESET_ALL}")
            log_info("Application exited")
            break
        else:
            print(f"{current_theme['error']}{i18n.get('invalid_option')}{Style.RESET_ALL}")
        try:
            input(f"\n{current_theme['primary']}{i18n.get('press_enter')}{Style.RESET_ALL}")
        except EOFError:
            break
        clear_screen()
        print(Fore.CYAN + BANNER + Style.RESET_ALL)


def main():
    setup_logging()
    load_config()
    log_info(f"Application started, version {VERSION}")
    parser = argparse.ArgumentParser(
        prog="Metadata-Worker", description="IL2CPP Metadata Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    extract_parser = subparsers.add_parser(
        "extract", help="Extract metadata from libunity.so"
    )
    extract_parser.add_argument("libunity", help="Path to libunity.so")
    extract_parser.add_argument("-o", "--output", required=True, help="Output path")
    extract_parser.add_argument(
        "-s", "--size", type=int, default=30_000_000, help="Max extraction size"
    )
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt extracted metadata")
    decrypt_parser.add_argument("input", help="Path to encrypted metadata")
    decrypt_parser.add_argument("-o", "--output", required=True, help="Output path")
    decrypt_parser.add_argument("-e", "--exclude", help="Exclude offsets (e.g., 1,2,3)")
    info_parser = subparsers.add_parser("info", help="Show metadata info")
    info_parser.add_argument("input", help="Path to metadata file")
    apk_parser = subparsers.add_parser(
        "apk", help="Extract metadata from APK or folder"
    )
    apk_parser.add_argument("input", help="Path to APK file or folder")
    apk_parser.add_argument("-o", "--output", required=True, help="Output path")
    apk_parser.add_argument(
        "-f", "--force", action="store_true", help="Force extract if encrypted"
    )
    menu_parser = subparsers.add_parser("menu", help="Interactive menu mode")
    args = parser.parse_args()
    if args.command and args.command != "menu":
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        loading_animation()
        check_for_updates()
    if args.command == "extract":
        if not os.path.isfile(args.libunity):
            print(f"{current_theme['error']}Error: {args.libunity} not found{Style.RESET_ALL}")
            log_error(f"File not found: {args.libunity}")
            sys.exit(1)
        result = extract_metadata(args.libunity, args.size)
        if result:
            metadata, _ = result
            with open(args.output, "wb") as f:
                f.write(metadata)
            print(f"{current_theme['success']}Metadata extracted to {args.output}{Style.RESET_ALL}")
    elif args.command == "decrypt":
        if not os.path.isfile(args.input):
            print(f"{current_theme['error']}Error: {args.input} not found{Style.RESET_ALL}")
            log_error(f"File not found: {args.input}")
            sys.exit(1)
        with open(args.input, "rb") as f:
            metadata = f.read()
        decrypt_metadata(metadata, args.output, args.exclude)
    elif args.command == "info":
        if not os.path.isfile(args.input):
            print(f"{current_theme['error']}Error: {args.input} not found{Style.RESET_ALL}")
            log_error(f"File not found: {args.input}")
            sys.exit(1)
        with open(args.input, "rb") as f:
            data = f.read(512)
        print(f"\n{current_theme['primary']}╔{'═'*58}╗{Style.RESET_ALL}")
        print(f"{current_theme['primary']}║{Style.RESET_ALL}  {'Metadata Info':^52}{current_theme['primary']}║{Style.RESET_ALL}")
        print(f"{current_theme['primary']}╚{'═'*58}╝{Style.RESET_ALL}")
        print(f"Magic: {data[:4].hex().upper()}")
        version, desc = get_metadata_version(data)
        print(f"Version: {version} ({desc})")
        print(f"File size: {os.path.getsize(args.input)} bytes")
        if data[:4] != METADATA_MAGIC:
            print(
                f"{current_theme['warning']}Warning: Invalid magic bytes - file may be encrypted{Style.RESET_ALL}"
            )
            decrypted, key = try_decrypt_metadata(data)
            if key:
                print(f"{current_theme['success']}Possible encryption key: {key}{Style.RESET_ALL}")
    elif args.command == "apk":
        if not os.path.exists(args.input):
            print(f"{current_theme['error']}Error: {args.input} not found{Style.RESET_ALL}")
            log_error(f"File not found: {args.input}")
            sys.exit(1)
        extract_from_apk(args.input, args.output, args.force)
    elif args.command == "menu":
        interactive_menu()
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
