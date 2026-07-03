import argparse
import collections
import json
import logging
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

try:
    import tkinter as tk
    from tkinter import filedialog

    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

if getattr(sys, "frozen", False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)
import i18n

CONFIG_FILE = os.path.join(script_dir, "config.json")
LOG_FILE = os.path.join(script_dir, "metadata-worker.log")
VERSION = "1.0.0"
METADATA_MAGIC = b"\xf1\xfa\x11\xfa"
METADATA_SIGNATURE = b"\x02\0\0\0\x7c\0\0\0\x06\x0b\0\0\0\x02\0\0\0"
METADATA_MARKER_64 = b"\x15\x00\x0c\x0c\x10\x1b\x23\0\0\0\0\0\x28\0\x2c\x10"
METADATA_MARKER_32 = b"\x00\x01\x01\x02\x01\x02\x02\x03"
METADATA_HEADER_MAGIC = b"\xaf\x1b\xb1\xfa"
COMMON_XOR_KEYS = [[0x53], [0xA3], [0x12, 0x34], [0xFF, 0xFF, 0xFF, 0xFF]]
SUPPORTED_VERSIONS = {
    16: "Unity 5.3",
    17: "Unity 5.4",
    19: "Unity 5.5",
    20: "Unity 5.6",
    21: "Unity 2017.1",
    22: "Unity 2017.2",
    23: "Unity 2017.3",
    24: "Unity 2017.4",
    25: "Unity 2018.1",
    26: "Unity 2018.2",
    27: "Unity 2018.3",
    28: "Unity 2018.4",
    29: "Unity 2019.1",
    30: "Unity 2019.2",
    31: "Unity 2019.3",
    32: "Unity 2019.4",
    33: "Unity 2020.1",
    34: "Unity 2020.2",
    35: "Unity 2020.3",
    36: "Unity 2021.1",
    37: "Unity 2021.2",
    38: "Unity 2021.3",
    39: "Unity 2022.1",
    40: "Unity 2022.2",
    41: "Unity 2022.3",
    42: "Unity 2023.1",
    43: "Unity 2023.2",
}
DEFAULT_CONFIG = {
    "language": "en",
    "recent_files": [],
    "last_output_dir": "",
}
config = DEFAULT_CONFIG.copy()
logger = None
ELFTOOLS_AVAILABLE = False

Style = None
Fore = None
tqdm = None

COLOR_PRIMARY = "\033[38;2;188;39;50m"
COLOR_SUCCESS = "\033[38;2;188;39;50m"
COLOR_WARNING = "\033[38;2;188;39;50m"
COLOR_ERROR = "\033[38;2;188;39;50m"
COLOR_ACCENT = "\033[38;2;188;39;50m"


def ensure_dependency(package_name, import_name=None):
    if import_name is None:
        import_name = package_name
    try:
        __import__(import_name)
        return True
    except ImportError:
        print(i18n.get("dep_missing").format(package=package_name))
        while True:
            try:
                ans = input(i18n.get("dep_install_prompt")).strip().lower()
            except EOFError:
                ans = "n"
            if ans in ("y", "n"):
                break
        if ans == "y":
            print(i18n.get("dep_installing").format(package=package_name))
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package_name]
                )
                __import__(import_name)
                return True
            except Exception as e:
                print(i18n.get("dep_failed").format(package=package_name, error=e))
                sys.exit(1)
        else:
            print(i18n.get("dep_cancelled"))
            sys.exit(1)


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
    global config
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved_config = json.load(f)
                config.update(saved_config)
                i18n.set_language(config.get("language", "en"))
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
    if Style:
        print(f"{COLOR_PRIMARY}{title}{Style.RESET_ALL}")
    else:
        print(title)
    recent = config.get("recent_files", [])
    if recent:
        print(f"{COLOR_PRIMARY}Recent files:{Style.RESET_ALL}" if Style else "Recent files:")
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
        print(f"{COLOR_ERROR}{i18n.get('file_not_found')}{Style.RESET_ALL}" if Style else i18n.get('file_not_found'))


def select_save_file_cli(title: str, defaultextension: str = "") -> str:
    if Style:
        print(f"{COLOR_PRIMARY}{title}{Style.RESET_ALL}")
    else:
        print(title)
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
        print(f"{COLOR_ERROR}{i18n.get('enter_path')}{Style.RESET_ALL}" if Style else i18n.get('enter_path'))


def select_folder_cli(title: str) -> str:
    if Style:
        print(f"{COLOR_PRIMARY}{title}{Style.RESET_ALL}")
    else:
        print(title)
    while True:
        try:
            path = input(i18n.get("path_to_folder")).strip()
        except EOFError:
            return ""
        if path.lower() == "q":
            return ""
        if os.path.isdir(path):
            return path
        print(f"{COLOR_ERROR}{i18n.get('folder_not_found')}{Style.RESET_ALL}" if Style else i18n.get('folder_not_found'))


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
    pass


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
            for j in range(klen, len(target)):
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
            f"{COLOR_SUCCESS}Found embedded metadata at offset {hex(idx)}{Style.RESET_ALL}"
        )
        log_info(f"Found metadata in libunity at offset {hex(idx)}")
        return idx
    return None


def map_vaddr_to_offset(va: int, load_segments: List[Tuple[int, int, int]]) -> int:
    for start, end, offset in load_segments:
        if start <= va < end:
            return va - start + offset
    raise ValueError(f"Virtual address {hex(va)} not found in LOAD segments")


def extract_metadata_pointer(libunity_path: str) -> Optional[int]:
    if not ELFTOOLS_AVAILABLE:
        return extract_metadata_pointer_alternative(libunity_path)
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
                print(f"{COLOR_ERROR}Error: .data section not found.{Style.RESET_ALL}")
                log_error(".data section not found")
                return None
            print(f"{COLOR_PRIMARY}Collecting relocations...{Style.RESET_ALL}")
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
            print(f"{COLOR_PRIMARY}Searching for metadata pointer...{Style.RESET_ALL}")
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
                    f"{COLOR_WARNING}Warning: No metadata pointer found via relocations, trying alternative method...{Style.RESET_ALL}"
                )
                return extract_metadata_pointer_alternative(libunity_path)
            elif len(candidates) > 1:
                print(
                    f"{COLOR_WARNING}Multiple candidates found, using first: {hex(candidates[0])}{Style.RESET_ALL}"
                )
            file_offsets = []
            for va in candidates:
                try:
                    file_offsets.append(map_vaddr_to_offset(va, load_segments))
                except ValueError:
                    continue
            if not file_offsets:
                return extract_metadata_pointer_alternative(libunity_path)
            return file_offsets[0]
    except Exception as e:
        print(f"{COLOR_ERROR}Error extracting metadata pointer: {e}{Style.RESET_ALL}")
        log_error(f"Pointer extraction error: {e}")
        return None


def extract_metadata_pointer_alternative(libunity_path: str) -> Optional[int]:
    try:
        with open(libunity_path, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(f"{COLOR_ERROR}Error reading libunity.so: {e}{Style.RESET_ALL}")
        log_error(f"Read error: {e}")
        return None
    print(f"{COLOR_PRIMARY}Scanning for metadata magic bytes...{Style.RESET_ALL}")
    idx = data.find(METADATA_MAGIC)
    if idx != -1:
        print(f"{COLOR_SUCCESS}Found metadata at offset: {hex(idx)}{Style.RESET_ALL}")
        return idx
    print(f"{COLOR_PRIMARY}Scanning for metadata signature...{Style.RESET_ALL}")
    idx = data.find(METADATA_SIGNATURE)
    if idx != -1:
        print(
            f"{COLOR_SUCCESS}Found metadata signature at offset: {hex(idx)}{Style.RESET_ALL}"
        )
        return idx
    print(f"{COLOR_ERROR}Error: No metadata found in libunity.so{Style.RESET_ALL}")
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
                print(f"{COLOR_SUCCESS}Auto-decrypted: {key}{Style.RESET_ALL}")
            version, desc = get_metadata_version(metadata)
            print(
                f"{COLOR_PRIMARY}Metadata version: {version} ({desc}){Style.RESET_ALL}"
            )
            return metadata, True
        metadata_ptr = extract_metadata_pointer(libunity_path)
        if metadata_ptr is None:
            return None
        with open(libunity_path, "rb") as libunity:
            libunity.seek(metadata_ptr)
            metadata = libunity.read(size)
            metadata, key = try_decrypt_metadata(metadata)
            if key:
                print(f"{COLOR_SUCCESS}Auto-decrypted: {key}{Style.RESET_ALL}")
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
                    f"{COLOR_SUCCESS}Metadata end marker found ({'64-bit' if is64bit else '32-bit'}).{Style.RESET_ALL}"
                )
            else:
                print(
                    f"{COLOR_ERROR}Warning: End marker not found, using full dump.{Style.RESET_ALL}"
                )
            version, desc = get_metadata_version(metadata)
            print(
                f"{COLOR_PRIMARY}Metadata version: {version} ({desc}){Style.RESET_ALL}"
            )
            print(
                f"{COLOR_PRIMARY}Metadata size: {len(metadata)} bytes{Style.RESET_ALL}"
            )
            return metadata, is64bit
    except (IOError, OSError, struct.error) as e:
        print(f"{COLOR_ERROR}Error extracting metadata: {e}{Style.RESET_ALL}")
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
                    fields[0] if len(struct_sig) <= 1 else fields
                )
            except struct.error:
                break
        if callback and callback(entries):
            found.append((offset, size, data))
    if not found:
        print(f"{COLOR_ERROR + Style.BRIGHT}Failed heuristic: {name}{Style.RESET_ALL}")
        return None, offsets_to_sizes
    found.sort(key=lambda x: x[1], reverse=not prefer_lowest)
    result = found[0]
    if result[:2] in remaining:
        remaining.remove(result[:2])
    print(f"{COLOR_PRIMARY}Found {name} at offset {result[0]}{Style.RESET_ALL}")
    log_debug(f"Found {name} at {result[0]}")
    return result, remaining


def unshuffle_metadata_header(header: bytes, full_size: int) -> Optional[List[int]]:
    if len(header) < 256:
        return None
    ints = list(struct.unpack("<64I", header[:256]))
    offset_instances = {}
    highest_offset = 0
    for val in ints:
        offset_instances[val] = offset_instances.get(val, 0) + 1
        if offset_instances[val] == 3 and val > 1000000:
            highest_offset = val
            break
    if highest_offset == 0:
        return None
    bytes_to_end = full_size - highest_offset
    last_size = 0
    for val in ints:
        if val % 4 != 0 or abs(bytes_to_end - val) > 4:
            continue
        last_size = val
        break
    if last_size == 0:
        return None
    pairs = [(highest_offset, last_size), (highest_offset, 0), (highest_offset, 0)]
    offsets_left = 28
    current_offset = highest_offset
    for _ in range(28):
        found = False
        for i in range(len(ints)):
            if ints[i] <= 0 or ints[i] % 4 != 0:
                continue
            for j in range(len(ints)):
                if ints[j] <= 0:
                    continue
                prev_offset = ints[j]
                prev_size = ints[i]
                if len(pairs) in (25, 28, 29, 30):
                    prev_offset, prev_size = min(prev_offset, prev_size), max(prev_offset, prev_size)
                else:
                    prev_offset, prev_size = max(prev_offset, prev_size), min(prev_offset, prev_size)
                delta = current_offset - prev_offset
                if abs(prev_size - delta) <= 4:
                    pairs.append((prev_offset, prev_size))
                    current_offset = prev_offset
                    offsets_left -= 1
                    ints[i] = 0
                    ints[j] = 0
                    found = True
                    break
            if found:
                break
        if not found:
            break
    if offsets_left != 0:
        return None
    pairs.reverse()
    offsets = [pair[0] for pair in pairs[:29]]
    if len(offsets) != 29 or any(off == 0 for off in offsets):
        return None
    return offsets


def decrypt_metadata(
    metadata: bytes,
    output_path: str,
    exclude_offsets: Optional[str] = None,
    skip_decrypt: bool = False,
) -> bool:
    log_info(f"Decrypting metadata to: {output_path}")
    try:
        print(f"{COLOR_SUCCESS}Starting metadata decryption...{Style.RESET_ALL}")
        if not skip_decrypt:
            metadata, key = try_decrypt_metadata(metadata)
            if key:
                print(f"{COLOR_SUCCESS}Auto-decrypted: {key}{Style.RESET_ALL}")
            else:
                print(
                    f"{COLOR_PRIMARY}Metadata is not encrypted or uses unknown encryption{Style.RESET_ALL}"
                )
        else:
            print(f"{COLOR_PRIMARY}Skipping auto-decryption.{Style.RESET_ALL}")
        version, desc = get_metadata_version(metadata)
        print(f"{COLOR_PRIMARY}Metadata version: {version} ({desc}){Style.RESET_ALL}")
        if version < 15 or version > 43:
            print(
                f"{COLOR_WARNING}Warning: Unknown metadata version {version}{Style.RESET_ALL}"
            )
        elif version > 38:
            print(
                f"{COLOR_WARNING}Warning: Version {version} may have limited support{Style.RESET_ALL}"
            )
        debug_path = os.path.join(script_dir, "debug-metadata.bin")
        with open(debug_path, "wb") as f:
            f.write(metadata)
        print(f"{COLOR_PRIMARY}Debug dump saved to {debug_path}{Style.RESET_ALL}")
        offset_candidates = find_offset_candidates(metadata)
        print(
            f"{COLOR_PRIMARY}Found {len(offset_candidates)} offset candidates{Style.RESET_ALL}"
        )
        if exclude_offsets:
            for excluded in exclude_offsets.replace(" ", "").split(","):
                if not excluded:
                    continue
                try:
                    todelete = int(excluded)
                    offset_candidates.remove(todelete)
                    print(f"{COLOR_PRIMARY}Excluded offset {todelete}{Style.RESET_ALL}")
                except (ValueError, KeyError):
                    print(
                        f"{COLOR_WARNING}Offset {excluded} not found in candidates{Style.RESET_ALL}"
                    )

        only_sizes = [
            x
            for x in [
                struct.unpack("<I", metadata[i : i + 4])[0] for i in range(0, 256, 4)
            ]
            if x not in offset_candidates
        ]

        offsets_to_sizes: List[Tuple[int, int]] = []
        for possible_offset in offset_candidates:
            found = False
            size_search_pool = only_sizes if possible_offset != 256 else [
                struct.unpack("<I", metadata[i : i + 4])[0] for i in range(0, 256, 4)
            ]
            for size in size_search_pool:
                if size != possible_offset and size != 0 and size < len(metadata) / 3:
                    if size + possible_offset == len(metadata):
                        offsets_to_sizes.append((possible_offset, size))
                        found = True
                        break
                    for next_offset in offset_candidates:
                        if possible_offset + size == next_offset and possible_offset != next_offset:
                            offsets_to_sizes.append((possible_offset, size))
                            found = True
                            break
                if found:
                    break
            if not found:
                is_256 = possible_offset == 256
                is_big_enough = possible_offset > len(metadata) / 3
                next_offset = None
                try:
                    idx = offset_candidates.index(possible_offset)
                    if idx + 1 < len(offset_candidates):
                        next_offset = offset_candidates[idx + 1]
                except ValueError:
                    pass
                is_size_big_enough = (next_offset is not None) and (next_offset - possible_offset > 4096)
                did_last_add_up = False
                if offsets_to_sizes:
                    last_pair_sum = sum(offsets_to_sizes[-1])
                    did_last_add_up = last_pair_sum == possible_offset
                if (is_256 or is_big_enough or is_size_big_enough) and (did_last_add_up or is_256 or not offsets_to_sizes):
                    size = (next_offset - possible_offset) if next_offset else len(metadata) - possible_offset
                    offsets_to_sizes.append((possible_offset, size))
                    print(f"{COLOR_PRIMARY}Offset {possible_offset} added with approximate size {size}{Style.RESET_ALL}")
                else:
                    only_sizes.append(possible_offset)

        offsets_to_sizes = sorted(offsets_to_sizes, key=lambda x: x[0])
        print(
            f"{COLOR_PRIMARY}Validated {len(offsets_to_sizes)} offset/size pairs{Style.RESET_ALL}"
        )
        reconstructed = bytearray(
            METADATA_HEADER_MAGIC + b"\x1f\x00\x00\x00\x00\x01\x00\x00" + b"\x00" * 244
        )
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

        def nestedTypes_cb(e):
            right_count, last_index, attempts = 0, 0, 0
            for idx in e:
                attempts += 1
                if idx > last_index:
                    right_count += 1
                else:
                    right_count -= 1
                if right_count > 256:
                    return True
                if right_count < -4 or idx > 0x01000000 or attempts > 512:
                    return False
                last_index = idx
            return True

        def interfaces_cb(e):
            for val in e:
                if 1024576 < val or val < 256:
                    return False
            return True

        def vtableMethods_cb(e):
            for val in e:
                if val != 1 and val & 0xE0000000 == 0:
                    return False
            return True

        def interfaceOffsets_cb(e):
            for type_idx, off in e:
                if off > 256 or 256 > type_idx or type_idx > 65535:
                    return False
            return True

        def typeDefinitions_cb(e):
            for entry in e:
                if entry[25] & 0xFF000000 != 0x02000000:
                    return False
            return True

        def images_cb(e):
            entries = e[:len(e) - 2]
            for entry in entries:
                if entry[7] != 1:
                    return False
            return True

        def fieldRefs_cb(e):
            for type_idx, field_idx in e:
                if type_idx < 256 or field_idx > 2048:
                    return False
            return True

        def referencedAssemblies_cb(e):
            if not e:
                return True
            mean = sum(e) / len(e)
            for val in e:
                if val > 256 or not 30 < mean < 40:
                    return False
            return True

        def attributeDataRange_cb(e):
            right = 0
            last_idx = e[0][1] if e else 0
            if last_idx != 0:
                return False
            for token, idx in e:
                if token & 0xFF000000 == 0:
                    right -= 10
                else:
                    right += 2
                if idx < last_idx:
                    right -= 2
                else:
                    right += 1
                if right > 2048:
                    return True
                elif right < -16:
                    return False
            return True

        def unresolvedIndirectCallParameterTypes_cb(e):
            for val in e:
                if val < 256 or val > 70000:
                    return False
            return True

        def unresolvedIndirectCallParameterTypeRanges_cb(e):
            expected = e[0][0] if e else 0
            for start, length in e:
                if start != expected:
                    return False
                expected += length
            return True

        def exportedTypeDefinitions_cb(e):
            for val in e:
                if val < 64 or val > 131072:
                    return False
            return True

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
            ("methods", token_cb(0x06000000), "<IIIIIIIHHHH", False, None),
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
            ("genericParameters", None, "<IIHHHH", True, None),
            ("genericParameterContraints", None, "<I", True, None),
            ("genericContainers", None, "<IIII", False, None),
            ("nestedTypes", nestedTypes_cb, "<I", False, None),
            ("interfaces", interfaces_cb, "<I", False, None),
            ("vtableMethods", vtableMethods_cb, "<I", False, None),
            ("interfaceOffsets", interfaceOffsets_cb, "<II", False, None),
            ("typeDefinitions", typeDefinitions_cb, "<IIIIIIIIIIIIIIIIHHHHHHHHII", False, None),
            ("images", images_cb, "<IIIIIIIIII", False, None),
            ("assemblies", token_cb(0x20000000), "<IIIIIIIIIIIIIIII", False, None),
            ("fieldRefs", fieldRefs_cb, "<II", False, None),
            ("referencedAssemblies", referencedAssemblies_cb, "<I", False, None),
            ("attributeData", None, None, False, b"NewFragmentBox"),
            ("attributeDataRange", attributeDataRange_cb, "<II", False, None),
            ("unresolvedIndirectCallParameterTypes", unresolvedIndirectCallParameterTypes_cb, "<I", False, None),
            ("unresolvedIndirectCallParameterTypeRanges", unresolvedIndirectCallParameterTypeRanges_cb, "<II", False, None),
            ("exportedTypeDefinitions", exportedTypeDefinitions_cb, "<I", False, None),
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
            print(f"{COLOR_WARNING}Heuristics only found {len(reconstructed_offsets)} sections, trying unshuffle...{Style.RESET_ALL}")
            unshuffled = unshuffle_metadata_header(metadata[:256], len(metadata))
            if unshuffled:
                reconstructed_offsets = unshuffled
                print(f"{COLOR_SUCCESS}Unshuffle succeeded.{Style.RESET_ALL}")
            else:
                print(f"{COLOR_WARNING}Unshuffle also failed.{Style.RESET_ALL}")

        if len(reconstructed_offsets) < 28:
            print(
                f"{COLOR_WARNING}Warning: Only found {len(reconstructed_offsets)} sections (expected 29){Style.RESET_ALL}"
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
        for i in range(min(28, len(reconstructed_offsets))):
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
        for _ in range(2):
            add_header_size(0)
        if reconstructed_offsets:
            last_offset = reconstructed_offsets[-1]
            last_size = len(metadata) - last_offset
            add_header_size(last_size)
            reconstructed += metadata[last_offset : last_offset + last_size]
        else:
            add_header_size(len(metadata))
            reconstructed += metadata
        if len(reconstructed) >= 256:
            reconstructed[252:256] = struct.pack(
                "<I", len(metadata) - struct.unpack("<I", reconstructed[248:252])[0]
            )
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, "output-metadata.dat")
        with open(output_path, "wb") as f:
            f.write(reconstructed)
        print(f"{COLOR_ACCENT + Style.BRIGHT}Output: {output_path}{Style.RESET_ALL}")
        print(f"{COLOR_SUCCESS}Metadata decrypted successfully!{Style.RESET_ALL}")
        log_info(f"Decrypted to {output_path}")
        return True
    except (IOError, OSError, struct.error) as e:
        print(f"{COLOR_ERROR}Error decrypting meta {e}{Style.RESET_ALL}")
        log_error(f"Decrypt error: {e}")
        return False


def print_menu():
    if not Style:
        return
    print()
    print(f"{COLOR_PRIMARY}┌{'─'*62}┐{Style.RESET_ALL}")
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {COLOR_SUCCESS}1{Style.RESET_ALL}. {i18n.get('menu_extract'): <57}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {COLOR_SUCCESS}2{Style.RESET_ALL}. {i18n.get('menu_decrypt'): <57}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {COLOR_SUCCESS}3{Style.RESET_ALL}. {i18n.get('menu_info'): <57}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {COLOR_WARNING}4{Style.RESET_ALL}. {i18n.get('menu_switch_lang'): <57}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {COLOR_ERROR}0{Style.RESET_ALL}. {i18n.get('menu_exit'): <57}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(f"{COLOR_PRIMARY}└{'─'*62}┘{Style.RESET_ALL}")


def menu_extract():
    clear_screen()
    print(f"\n{COLOR_PRIMARY}┌{'─'*58}┐{Style.RESET_ALL}")
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {i18n.get('extract_title'):^56}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(f"{COLOR_PRIMARY}└{'─'*58}┘{Style.RESET_ALL}")
    libunity = select_file(
        i18n.get("select_libunity"), [("SO files", ".so"), ("All files", ".*")]
    )
    if not libunity:
        print(f"{COLOR_ERROR}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('libunity')}{libunity}")
    output = select_save_file(
        i18n.get("save_metadata"), [("DAT files", ".dat"), ("All files", ".*")], ".dat"
    )
    if not output:
        print(f"{COLOR_ERROR}{i18n.get('no_output_path')}{Style.RESET_ALL}")
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
        print(f"{COLOR_SUCCESS}{i18n.get('extracted_to')}{output}{Style.RESET_ALL}")


def menu_decrypt():
    clear_screen()
    print(f"\n{COLOR_PRIMARY}┌{'─'*58}┐{Style.RESET_ALL}")
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {i18n.get('decrypt_title'):^56}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(f"{COLOR_PRIMARY}└{'─'*58}┘{Style.RESET_ALL}")
    input_file = select_file(
        i18n.get("select_encrypted"), [("DAT files", ".dat"), ("All files", ".*")]
    )
    if not input_file:
        print(f"{COLOR_ERROR}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('input')}{input_file}")
    output = select_save_file(
        i18n.get("save_decrypted"), [("DAT files", ".dat"), ("All files", ".*")], ".dat"
    )
    if not output:
        print(f"{COLOR_ERROR}{i18n.get('no_output_path')}{Style.RESET_ALL}")
        return
    try:
        exclude = input(i18n.get("exclude_offsets_prompt")).strip() or None
        skip = input(i18n.get("skip_decrypt_prompt")).strip().lower() == "y"
        with open(input_file, "rb") as f:
            metadata = f.read()
        decrypt_metadata(metadata, output, exclude, skip_decrypt=skip)
    except Exception as e:
        print(f"{COLOR_ERROR}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_info():
    clear_screen()
    print(f"\n{COLOR_PRIMARY}┌{'─'*58}┐{Style.RESET_ALL}")
    print(
        f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {i18n.get('info_title'):^56}{COLOR_PRIMARY}│{Style.RESET_ALL}"
    )
    print(f"{COLOR_PRIMARY}└{'─'*58}┘{Style.RESET_ALL}")
    input_file = select_file(
        i18n.get("select_metadata"), [("DAT files", ".dat"), ("All files", ".*")]
    )
    if not input_file:
        print(f"{COLOR_ERROR}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('file')}{input_file}")
    try:
        with open(input_file, "rb") as f:
            data = f.read(512)
        print(f"\n{COLOR_PRIMARY}┌{'─'*58}┐{Style.RESET_ALL}")
        print(
            f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {i18n.get('metadata_info_title'):^56}{COLOR_PRIMARY}│{Style.RESET_ALL}"
        )
        print(f"{COLOR_PRIMARY}└{'─'*58}┘{Style.RESET_ALL}")
        print(f"{i18n.get('magic')}{data[:4].hex().upper()}")
        version, desc = get_metadata_version(data)
        print(f"{i18n.get('version')}{version} ({desc})")
        print(f"{i18n.get('file_size')}{os.path.getsize(input_file)} bytes")
        if data[:4] != METADATA_MAGIC:
            print(
                f"{COLOR_WARNING}{i18n.get('warning_invalid_magic')}{Style.RESET_ALL}"
            )
        decrypted, key = try_decrypt_metadata(data)
        if key:
            print(
                f"{COLOR_SUCCESS}{i18n.get('possible_encryption')}{key}{Style.RESET_ALL}"
            )
    except Exception as e:
        print(f"{COLOR_ERROR}{i18n.get('error')}{e}{Style.RESET_ALL}")


def interactive_menu():
    clear_screen()
    if Style:
        print(COLOR_PRIMARY + i18n.BANNER + Style.RESET_ALL)
    else:
        print(i18n.BANNER)
    loading_animation()
    while True:
        print_menu()
        try:
            choice = input(
                f"{COLOR_PRIMARY}{i18n.get('select_option')}{Style.RESET_ALL}: "
            ).strip()
        except EOFError:
            print(f"\n{COLOR_SUCCESS}{i18n.get('exiting')}{Style.RESET_ALL}")
            break
        if choice == "1":
            menu_extract()
        elif choice == "2":
            menu_decrypt()
        elif choice == "3":
            menu_info()
        elif choice == "4":
            lang = i18n.toggle_language()
            config["language"] = lang
            save_config()
            print(
                f"{COLOR_SUCCESS}{i18n.get('lang_changed')}{lang.upper()}{Style.RESET_ALL}"
            )
        elif choice == "0":
            print(f"{COLOR_SUCCESS}{i18n.get('exiting')}{Style.RESET_ALL}")
            log_info("Application exited")
            break
        else:
            print(f"{COLOR_ERROR}{i18n.get('invalid_option')}{Style.RESET_ALL}")
        try:
            input(f"\n{COLOR_PRIMARY}{i18n.get('press_enter')}{Style.RESET_ALL}")
        except EOFError:
            break
        clear_screen()
        if Style:
            print(COLOR_PRIMARY + i18n.BANNER + Style.RESET_ALL)
        else:
            print(i18n.BANNER)


def main():
    global Style, Fore, tqdm, ELFTOOLS_AVAILABLE
    ensure_dependency("colorama")
    ensure_dependency("tqdm")
    ensure_dependency("pyelftools", "elftools")
    from colorama import Fore as _Fore, Style as _Style
    from colorama import init as colorama_init
    from tqdm import tqdm as _tqdm

    Style = _Style
    Fore = _Fore
    tqdm = _tqdm
    globals()["Style"] = Style
    globals()["Fore"] = Fore
    globals()["tqdm"] = tqdm
    try:
        from elftools.elf.elffile import ELFFile
        globals()["ELFFile"] = ELFFile
        ELFTOOLS_AVAILABLE = True
    except ImportError:
        ELFTOOLS_AVAILABLE = False

    colorama_init(autoreset=True)
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
    decrypt_parser.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Skip auto-decryption, only heuristic reconstruction",
    )
    info_parser = subparsers.add_parser("info", help="Show metadata info")
    info_parser.add_argument("input", help="Path to metadata file")
    menu_parser = subparsers.add_parser("menu", help="Interactive menu mode")
    args = parser.parse_args()
    if args.command and args.command != "menu":
        print(COLOR_PRIMARY + i18n.BANNER + Style.RESET_ALL)
        loading_animation()
        if args.command == "extract":
            if not os.path.isfile(args.libunity):
                print(f"{COLOR_ERROR}Error: {args.libunity} not found{Style.RESET_ALL}")
                log_error(f"File not found: {args.libunity}")
                sys.exit(1)
            result = extract_metadata(args.libunity, args.size)
            if result:
                metadata, _ = result
                with open(args.output, "wb") as f:
                    f.write(metadata)
                print(
                    f"{COLOR_SUCCESS}Metadata extracted to {args.output}{Style.RESET_ALL}"
                )
        elif args.command == "decrypt":
            if not os.path.isfile(args.input):
                print(f"{COLOR_ERROR}Error: {args.input} not found{Style.RESET_ALL}")
                log_error(f"File not found: {args.input}")
                sys.exit(1)
            with open(args.input, "rb") as f:
                metadata = f.read()
            decrypt_metadata(
                metadata, args.output, args.exclude, skip_decrypt=args.no_decrypt
            )
        elif args.command == "info":
            if not os.path.isfile(args.input):
                print(f"{COLOR_ERROR}Error: {args.input} not found{Style.RESET_ALL}")
                log_error(f"File not found: {args.input}")
                sys.exit(1)
            with open(args.input, "rb") as f:
                data = f.read(512)
            print(f"\n{COLOR_PRIMARY}┌{'─'*58}┐{Style.RESET_ALL}")
            print(
                f"{COLOR_PRIMARY}│{Style.RESET_ALL}  {i18n.get('metadata_info_title'):^56}{COLOR_PRIMARY}│{Style.RESET_ALL}"
            )
            print(f"{COLOR_PRIMARY}└{'─'*58}┘{Style.RESET_ALL}")
            print(f"{i18n.get('magic')}{data[:4].hex().upper()}")
            version, desc = get_metadata_version(data)
            print(f"{i18n.get('version')}{version} ({desc})")
            print(f"{i18n.get('file_size')}{os.path.getsize(args.input)} bytes")
            if data[:4] != METADATA_MAGIC:
                print(
                    f"{COLOR_WARNING}{i18n.get('warning_invalid_magic')}{Style.RESET_ALL}"
                )
            decrypted, key = try_decrypt_metadata(data)
            if key:
                print(f"{COLOR_SUCCESS}{i18n.get('possible_encryption')}{key}{Style.RESET_ALL}")
        elif args.command == "menu":
            interactive_menu()
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
