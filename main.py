import argparse
import itertools
import json
import logging
import mmap
import os
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Iterator, List, Optional, Sequence, Tuple

tk: Any = None
filedialog: Any = None
TKINTER_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import filedialog

    TKINTER_AVAILABLE = True
except ImportError:
    pass

if getattr(sys, "frozen", False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)
import i18n

VERSION = "1.1.0"
CONFIG_FILE = os.path.join(script_dir, "config.json")
LOG_FILE = os.path.join(script_dir, "metadata-worker.log")
DUMP_FILE = os.path.join(script_dir, "debug-metadata.bin")
EXTRACTED_NAME = "metadata.dat"
RECONSTRUCTED_NAME = "output-metadata.dat"

METADATA_MAGIC = b"\xf1\xfa\x11\xfa"
METADATA_HEADER_MAGIC = b"\xaf\x1b\xb1\xfa"
METADATA_HEADER_SIZE = 256
METADATA_VERSION_STUB = b"\x1f\x00\x00\x00"
METADATA_DATA_OFFSET_STUB = b"\x00\x01\x00\x00"
METADATA_SIGNATURE = b"\x02\0\0\0\x7c\0\0\0\x06\x0b\0\0\0\x02\0\0\0"
METADATA_MARKER_64 = b"\x15\x00\x0c\x0c\x10\x1b\x23\0\0\0\0\0\x28\0\x2c\x10"
METADATA_MARKER_32 = b"\x00\x01\x01\x02\x01\x02\x02\x03"

HEADER_SLOTS = 31
SECTION_SLOTS = 28
DEFAULT_MAX_SIZE = 30_000_000
PROBE_SIZE = 0x1000
MAX_RECENT_FILES = 10
MENU_RECENT_LIMIT = 5
LOG_MAX_BYTES = 2 * 1024 * 1024
LOG_BACKUP_COUNT = 3
DENSITY_WINDOW = 4096
DENSITY_THRESHOLD = 0.75
XXTEA_DELTA = 0x9E3779B9
STRIPED_XOR_KEYS = (0xA3, 0x53)
STRIPED_XOR_STRIPE = 0x1000
RC4_KEYS = (b"NEP2", b"Tarkov", b"wanzg")
XXTEA_KEYS = (
    b"\x00" * 16,
    b"\xff" * 16,
    b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 2,
)

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

config: dict = DEFAULT_CONFIG.copy()
logger: Optional[logging.Logger] = None
ELFTOOLS_AVAILABLE = False
ELFFile: Any = None
dump_debug = True

COLOR_PRIMARY = "\033[38;2;188;39;50m"
COLOR_SUCCESS = "\033[38;2;0;200;0m"
COLOR_WARNING = "\033[38;2;255;165;0m"
COLOR_ERROR = "\033[38;2;255;50;50m"
COLOR_ACCENT = "\033[38;2;0;150;255m"


class StyleFallback:
    RESET_ALL = ""
    BRIGHT = ""


class TqdmFallback:
    def __init__(self, iterable: Any = None, **_: Any) -> None:
        self.iterable: Any = [] if iterable is None else iterable

    def __iter__(self) -> Iterator[Any]:
        return iter(self.iterable)

    def __enter__(self) -> "TqdmFallback":
        return self

    def __exit__(self, *_: Any) -> bool:
        return False

    def update(self, n: int = 1) -> None:
        return None

    def set_description(self, *_: Any) -> None:
        return None

    def close(self) -> None:
        return None


Style: Any = StyleFallback
tqdm: Any = TqdmFallback


def paint(text: str, color: str, bright: bool = False) -> str:
    prefix = color + (Style.BRIGHT if bright else "")
    return f"{prefix}{text}{Style.RESET_ALL}"


def prompt(text: str) -> Optional[str]:
    try:
        return input(text).strip().strip('"').strip()
    except (EOFError, KeyboardInterrupt):
        return None


def ensure_dependency(package_name: str, import_name: Optional[str] = None) -> bool:
    module_name = import_name or package_name
    try:
        __import__(module_name)
        return True
    except ImportError:
        print(i18n.get("dep_missing").format(package=package_name))
        answer = prompt(i18n.get("dep_install_prompt").format(package=package_name))
        if answer is None or answer.lower() not in ("y", "yes"):
            print(i18n.get("dep_cancelled"))
            sys.exit(1)
        print(i18n.get("dep_installing").format(package=package_name))
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", package_name]
            )
            __import__(module_name)
            return True
        except Exception as error:
            print(i18n.get("dep_failed").format(package=package_name, error=error))
            sys.exit(1)


def setup_logging() -> None:
    global logger
    logger = logging.getLogger("MetadataWorker")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)
    except (IOError, OSError):
        pass


def log_info(message: str) -> None:
    if logger:
        logger.info(message)


def log_error(message: str) -> None:
    if logger:
        logger.error(message)


def log_debug(message: str) -> None:
    if logger:
        logger.debug(message)


def log_warning(message: str) -> None:
    if logger:
        logger.warning(message)


def load_config() -> None:
    if not os.path.exists(CONFIG_FILE):
        return
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            saved = json.load(handle)
    except (json.JSONDecodeError, IOError, OSError) as error:
        log_warning(f"Failed to read config: {error}")
        return
    if not isinstance(saved, dict):
        log_warning("Config root is not an object")
        return
    language = saved.get("language")
    if isinstance(language, str):
        config["language"] = language
    recent = saved.get("recent_files")
    if isinstance(recent, list):
        config["recent_files"] = [
            path
            for path in recent[:MAX_RECENT_FILES]
            if isinstance(path, str) and os.path.isfile(path)
        ]
    last_output_dir = saved.get("last_output_dir")
    config["last_output_dir"] = (
        last_output_dir if isinstance(last_output_dir, str) else ""
    )
    i18n.set_language(config["language"])


def save_config() -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, ensure_ascii=False)
    except (IOError, OSError) as error:
        log_error(f"Failed to save config: {error}")


def add_recent_file(path: str) -> None:
    recent = [item for item in config.get("recent_files", []) if item != path]
    recent.insert(0, path)
    config["recent_files"] = recent[:MAX_RECENT_FILES]
    save_config()


def clear_screen() -> None:
    if not sys.stdout or not sys.stdout.isatty():
        return
    if os.name == "nt":
        os.system("cls")
    else:
        sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


BOX_WIDTH = 58
MENU_WIDTH = 62


def box_top(width: int = BOX_WIDTH) -> None:
    print(paint(f"┌{'─' * width}┐", COLOR_PRIMARY))


def box_title(text: str, width: int = BOX_WIDTH) -> None:
    print(paint(f"│  {text[: width - 2]:^{width - 2}}│", COLOR_PRIMARY))
    print(paint(f"└{'─' * width}┘", COLOR_PRIMARY))


def select_file_cli(title: str) -> str:
    print(paint(title, COLOR_PRIMARY))
    recent = config.get("recent_files", [])[:MENU_RECENT_LIMIT]
    if recent:
        print(paint(i18n.get("recent_files"), COLOR_PRIMARY))
        for index, path in enumerate(recent, 1):
            print(f"  [{index}] {path}")
    while True:
        entered = prompt(i18n.get("path_to_file"))
        if entered is None or entered.lower() == "q":
            return ""
        path = os.path.expanduser(entered)
        if path.isdigit() and 1 <= int(path) <= len(recent):
            path = recent[int(path) - 1]
        if os.path.isfile(path):
            add_recent_file(path)
            return path
        print(paint(i18n.get("file_not_found"), COLOR_ERROR))


def select_save_file_cli(title: str, defaultextension: str = "") -> str:
    print(paint(title, COLOR_PRIMARY))
    while True:
        entered = prompt(i18n.get("path_to_save"))
        if entered is None or entered.lower() == "q":
            return ""
        path = os.path.expanduser(entered)
        if not path:
            print(paint(i18n.get("enter_path"), COLOR_ERROR))
            continue
        if defaultextension and not path.endswith(defaultextension):
            path += defaultextension
        return path


def tk_dialog(runner: Callable, title: str, **kwargs: Any) -> Optional[str]:
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        return runner(title=title, **kwargs) or ""
    except Exception as error:
        log_debug(f"tkinter dialog unavailable: {error}")
        return None
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass


def dialog_defaults() -> dict:
    last_dir = config.get("last_output_dir") or os.path.expanduser("~")
    return {"initialdir": last_dir}


def select_file(title: str, filetypes: list) -> str:
    if TKINTER_AVAILABLE:
        path = tk_dialog(
            filedialog.askopenfilename, title, filetypes=filetypes, **dialog_defaults()
        )
        if path is not None:
            if path:
                add_recent_file(path)
            return path
    return select_file_cli(title)


def select_save_file(title: str, filetypes: list, defaultextension: str = "") -> str:
    if TKINTER_AVAILABLE:
        path = tk_dialog(
            filedialog.asksaveasfilename,
            title,
            filetypes=filetypes,
            defaultextension=defaultextension,
            **dialog_defaults(),
        )
        if path is not None:
            if path:
                config["last_output_dir"] = os.path.dirname(os.path.abspath(path))
                save_config()
            return path
    path = select_save_file_cli(title, defaultextension)
    if path:
        config["last_output_dir"] = os.path.dirname(os.path.abspath(path))
        save_config()
    return path


_spinner_stop = threading.Event()


def _spin(text: str) -> None:
    while not _spinner_stop.is_set():
        for char in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
            if _spinner_stop.is_set():
                break
            sys.stdout.write(f"\r{paint(char + ' ' + text, COLOR_PRIMARY)}")
            sys.stdout.flush()
            time.sleep(0.08)
    sys.stdout.write("\r" + " " * (len(text) + 4) + "\r")
    sys.stdout.flush()


@contextmanager
def loading(text: str) -> Iterator[None]:
    _spinner_stop.clear()
    thread = threading.Thread(target=_spin, args=(text,), daemon=True)
    thread.start()
    try:
        yield
    finally:
        _spinner_stop.set()
        thread.join(timeout=1.0)


def write_output(data: bytes, path: str, default_name: str) -> str:
    if os.path.isdir(path):
        path = os.path.join(path, default_name)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def find_pattern(path: str, pattern: bytes) -> List[int]:
    hits: List[int] = []
    with open(path, "rb") as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            return hits
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            start = 0
            while True:
                index = mapped.find(pattern, start)
                if index == -1:
                    break
                hits.append(index)
                start = index + 1
    return hits


def is_valid_metadata(data: bytes) -> bool:
    return len(data) >= 4 and data.startswith(METADATA_MAGIC)


def get_metadata_version(data: bytes) -> Tuple[int, str]:
    if len(data) < 8:
        return -1, "Unknown"
    version = struct.unpack_from("<I", data, 4)[0]
    return version, SUPPORTED_VERSIONS.get(version, f"Unknown (v{version})")


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key or not data:
        return data
    repeats = (len(data) + len(key) - 1) // len(key)
    stream = (key * repeats)[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(
        len(data), "big"
    )


def decrypt_xor(data: bytes, key: Sequence[int]) -> bytes:
    if not key:
        return data
    return xor_bytes(data, bytes(key))


def decrypt_striped_xor(data: bytes, key: int = 0xA3) -> bytes:
    out = bytearray(data)
    for start in range(0, len(out), STRIPED_XOR_STRIPE * 2):
        for index in range(start, min(start + STRIPED_XOR_STRIPE, len(out))):
            out[index] ^= key
    return bytes(out)


def decrypt_rc4(data: bytes, key: bytes = b"wanzg") -> bytes:
    if not key:
        return data
    state = list(range(256))
    key_length = len(key)
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % key_length]) & 0xFF
        state[i], state[j] = state[j], state[i]
    stream = bytearray(len(data))
    i = 0
    j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        stream[n] = state[(state[i] + state[j]) & 0xFF]
    return xor_bytes(data, bytes(stream))


def decrypt_xxtea(data: bytes, key: bytes, max_words: int = PROBE_SIZE) -> bytes:
    if len(data) < 8 or len(key) < 16:
        return data
    words = min(len(data) // 4, max_words)
    words -= words % 2
    if words < 2:
        return data
    keys = struct.unpack_from("<4I", key, 0)
    values = list(struct.unpack_from(f"<{words}I", data, 0))
    rounds = 6 + 52 // words
    total = (rounds * XXTEA_DELTA) & 0xFFFFFFFF
    y = values[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(words - 1, 0, -1):
            z = values[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
                (total ^ y) + (keys[(p & 3) ^ e] ^ z)
            )
            values[p] = (values[p] - mx) & 0xFFFFFFFF
            y = values[p]
        z = values[words - 1]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
            (total ^ y) + (keys[e] ^ z)
        )
        values[0] = (values[0] - mx) & 0xFFFFFFFF
        y = values[0]
        total = (total - XXTEA_DELTA) & 0xFFFFFFFF
    return struct.pack(f"<{words}I", *values) + data[words * 4 :]


def auto_header_xor_key(data: bytes) -> Optional[List[int]]:
    if len(data) < 8:
        return None
    key = [data[index] ^ METADATA_MAGIC[index] for index in range(4)]
    if len(set(key)) == 1 and key[0] != 0:
        return key
    return None


def auto_wanzg_key(data: bytes) -> Optional[List[int]]:
    if len(data) < 0x120:
        return None
    target = b"\x00" * 8 + b"\x01\x00\x00\x00"
    for index in range(0x100, 0x118):
        if index + len(target) > len(data):
            break
        key = [data[index + offset] ^ target[offset] for offset in range(len(target))]
        if key[0] == key[4] and key[1] == key[5] and key[2] == key[6]:
            return key[:5]
    return None


def auto_find_xor_key(data: bytes) -> Optional[List[int]]:
    if len(data) < 0x120:
        return None
    target = b"\x00" * 8 + b"\x01\x00\x00\x00"
    limit = min(0x140, len(data) - len(target))
    for index in range(0x100, max(0x100, limit)):
        key = [data[index + offset] ^ target[offset] for offset in range(len(target))]
        for period in range(3, len(key) + 1):
            if all(
                key[position] == key[position % period]
                for position in range(period, len(key))
            ):
                return key[:period]
    return None


def try_decrypt_metadata(data: bytes) -> Tuple[bytes, Optional[str]]:
    if is_valid_metadata(data):
        return data, None
    attempts: List[Tuple[str, Callable[[bytes], bytes]]] = []
    header_key = auto_header_xor_key(data)
    if header_key:
        attempts.append(
            (
                f"HEADER-XOR:{header_key}",
                lambda chunk, k=header_key: decrypt_xor(chunk, k),
            )
        )
    wanzg_key = auto_wanzg_key(data)
    if wanzg_key:
        attempts.append(
            (f"WANZG:{wanzg_key}", lambda chunk, k=wanzg_key: decrypt_xor(chunk, k))
        )
    scan_key = auto_find_xor_key(data)
    if scan_key:
        attempts.append(
            (f"AUTO-XOR:{scan_key}", lambda chunk, k=scan_key: decrypt_xor(chunk, k))
        )
    for key in STRIPED_XOR_KEYS:
        attempts.append(
            (
                f"STRIPED-XOR-0x{key:02X}",
                lambda chunk, k=key: decrypt_striped_xor(chunk, k),
            )
        )
    for key in RC4_KEYS:
        attempts.append(
            (f"RC4-{key.decode()}", lambda chunk, k=key: decrypt_rc4(chunk, k))
        )
    for key in XXTEA_KEYS:
        attempts.append(
            (
                f"XXTEA-{key.hex()}",
                lambda chunk, k=key: decrypt_xxtea(chunk, k, len(chunk) // 4),
            )
        )
    for label, cipher in attempts:
        if is_valid_metadata(cipher(data[:PROBE_SIZE])):
            return cipher(data), label
    return data, None


def is_elf_file(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except (IOError, OSError):
        return False


def find_embedded_metadata(path: str) -> Optional[int]:
    hits = find_pattern(path, METADATA_MAGIC)
    if not hits:
        return None
    fallback: Optional[int] = None
    with open(path, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        for offset in hits:
            if offset + 8 > size:
                continue
            handle.seek(offset + 4)
            version = struct.unpack("<I", handle.read(4))[0]
            log_debug(f"Metadata magic at {hex(offset)}, version field {version}")
            if version in SUPPORTED_VERSIONS or version < 0x100:
                return offset
            if fallback is None:
                fallback = offset
    return fallback


def map_vaddr_to_offset(
    va: int, load_segments: List[Tuple[int, int, int]]
) -> Optional[int]:
    for start, end, offset in load_segments:
        if start <= va < end:
            return va - start + offset
    return None


def collect_load_segments(elf: Any) -> List[Tuple[int, int, int]]:
    segments = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or segment["p_filesz"] == 0:
            continue
        start = segment["p_vaddr"]
        segments.append((start, start + segment["p_filesz"], segment["p_offset"]))
    return sorted(segments)


def extract_metadata_pointer(libunity_path: str) -> Optional[int]:
    if not ELFTOOLS_AVAILABLE:
        return extract_metadata_pointer_alternative(libunity_path)
    try:
        with open(libunity_path, "rb") as libunity:
            elf = ELFFile(libunity)
            is64bit = elf.elfclass == 64
            load_segments = collect_load_segments(elf)
            data_section = elf.get_section_by_name(".data")
            if not data_section:
                print(paint(i18n.get("data_section_missing"), COLOR_ERROR))
                log_error(".data section not found")
                return None
            data_start = data_section["sh_addr"]
            data_end = data_start + data_section["sh_size"]
            print(paint(i18n.get("collecting_relocations"), COLOR_PRIMARY))
            log_debug("Collecting relocations")
            pointers: List[int] = []
            for section in elf.iter_sections():
                if section.header["sh_type"] not in ("SHT_REL", "SHT_RELA"):
                    continue
                total = (
                    section.num_relocations()
                    if hasattr(section, "num_relocations")
                    else None
                )
                for relocation in tqdm(
                    section.iter_relocations(),
                    colour="green",
                    unit="rel",
                    total=total,
                    leave=False,
                ):
                    address = relocation["r_offset"]
                    if not data_start <= address < data_end:
                        continue
                    if is64bit:
                        if "r_addend" not in relocation.entry:
                            continue
                        pointer = relocation["r_addend"]
                    else:
                        offset = map_vaddr_to_offset(address, load_segments)
                        if offset is None:
                            continue
                        libunity.seek(offset)
                        raw = libunity.read(4)
                        if len(raw) != 4:
                            continue
                        pointer = struct.unpack("<I", raw)[0]
                    if pointer > 16:
                        pointers.append(pointer)
            print(paint(i18n.get("searching_pointer"), COLOR_PRIMARY))
            candidates: List[int] = []
            for pointer in tqdm(pointers, colour="green", unit="rel", leave=False):
                offset = map_vaddr_to_offset(pointer - 16, load_segments)
                if offset is None:
                    offset = pointer - 16
                if offset < 0:
                    continue
                libunity.seek(offset)
                if libunity.read(len(METADATA_SIGNATURE)) == METADATA_SIGNATURE:
                    candidates.append(pointer)
            if not candidates:
                print(paint(i18n.get("no_pointer_relocations"), COLOR_WARNING))
                return extract_metadata_pointer_alternative(libunity_path)
            if len(candidates) > 1:
                print(
                    paint(
                        i18n.get("multiple_candidates").format(
                            offset=hex(candidates[0])
                        ),
                        COLOR_WARNING,
                    )
                )
            for pointer in candidates:
                offset = map_vaddr_to_offset(pointer, load_segments)
                if offset is not None:
                    log_info(
                        f"Metadata pointer at vaddr {hex(pointer)} offset {hex(offset)}"
                    )
                    return offset
            return extract_metadata_pointer_alternative(libunity_path)
    except Exception as error:
        print(paint(f"{i18n.get('error')}{error}", COLOR_ERROR))
        log_error(f"Pointer extraction error: {error}")
        return None


def extract_metadata_pointer_alternative(libunity_path: str) -> Optional[int]:
    print(paint(i18n.get("scanning_magic"), COLOR_PRIMARY))
    embedded = find_embedded_metadata(libunity_path)
    if embedded is not None:
        print(
            paint(
                i18n.get("found_at_offset").format(offset=hex(embedded)), COLOR_SUCCESS
            )
        )
        return embedded
    print(paint(i18n.get("scanning_signature"), COLOR_PRIMARY))
    for offset in find_pattern(libunity_path, METADATA_SIGNATURE):
        print(
            paint(i18n.get("found_at_offset").format(offset=hex(offset)), COLOR_SUCCESS)
        )
        return offset
    print(paint(i18n.get("no_metadata_in_libunity"), COLOR_ERROR))
    return None


def truncate_at_end_marker(metadata: bytes) -> Tuple[bytes, bool]:
    index = metadata.find(METADATA_MARKER_64)
    is64bit = True
    if index == -1:
        index = metadata.find(METADATA_MARKER_32)
        is64bit = False
    if index == -1:
        print(paint(i18n.get("end_marker_missing"), COLOR_WARNING))
        return metadata, is64bit
    index += (4 - index % 4) % 4
    if 0 < index <= len(metadata):
        metadata = metadata[:index]
    print(
        paint(
            i18n.get("end_marker_found").format(bits=64 if is64bit else 32),
            COLOR_SUCCESS,
        )
    )
    return metadata, is64bit


def extract_metadata(
    libunity_path: str, size: int = DEFAULT_MAX_SIZE
) -> Optional[Tuple[bytes, bool]]:
    log_info(f"Extracting metadata from: {libunity_path}")
    if not is_elf_file(libunity_path):
        print(paint(i18n.get("warning_not_elf"), COLOR_WARNING))
    try:
        embedded_offset = find_embedded_metadata(libunity_path)
        if embedded_offset is not None:
            print(
                paint(
                    i18n.get("found_embedded").format(offset=hex(embedded_offset)),
                    COLOR_SUCCESS,
                )
            )
            offset = embedded_offset
        else:
            offset = extract_metadata_pointer(libunity_path)
            if offset is None:
                return None
        with open(libunity_path, "rb") as handle:
            handle.seek(offset)
            metadata = handle.read(size)
        metadata, key = try_decrypt_metadata(metadata)
        if key:
            print(paint(i18n.get("auto_decrypted").format(key=key), COLOR_SUCCESS))
        version, desc = get_metadata_version(metadata)
        print(
            paint(
                i18n.get("metadata_version").format(version=version, desc=desc),
                COLOR_PRIMARY,
            )
        )
        metadata, is64bit = truncate_at_end_marker(metadata)
        print(
            paint(i18n.get("metadata_size").format(size=len(metadata)), COLOR_PRIMARY)
        )
        log_info(
            f"Extracted {len(metadata)} bytes, is64bit={is64bit}, version={version}"
        )
        return metadata, is64bit
    except (IOError, OSError, struct.error, ValueError) as error:
        print(paint(f"{i18n.get('error')}{error}", COLOR_ERROR))
        log_error(f"Extract error: {error}")
        return None


def find_offset_candidates(metadata: bytes) -> List[int]:
    fields: List[int] = []
    limit = min(METADATA_HEADER_SIZE, len(metadata) - len(metadata) % 4)
    for index in range(0, limit - 3, 4):
        value = struct.unpack_from("<I", metadata, index)[0]
        if 0 < value < len(metadata):
            fields.append(value)
    candidates: List[int] = []
    for field in fields:
        if field < 8192 or field % 4 != 0:
            if field == 256:
                candidates.append(field)
            continue
        if field > len(metadata) / 3:
            candidates.append(field)
            continue
        behind = metadata[field - DENSITY_WINDOW : field]
        ahead = metadata[field : field + DENSITY_WINDOW]
        zeroes_behind = behind.count(b"\0")
        zeroes_ahead = ahead.count(b"\0")
        counter_behind = Counter(behind)
        counter_ahead = Counter(ahead)
        keys = set(counter_behind) | set(counter_ahead)
        distance = sum(
            abs(counter_behind.get(k, 0) - counter_ahead.get(k, 0)) / DENSITY_WINDOW
            for k in keys
        )
        score = abs(zeroes_behind - zeroes_ahead) / 512 + distance
        if score > DENSITY_THRESHOLD:
            candidates.append(field)
    return sorted(set(candidates))


def build_offsets_to_sizes(
    metadata: bytes, offset_candidates: List[int]
) -> List[Tuple[int, int]]:
    fields = [
        struct.unpack_from("<I", metadata, index)[0]
        for index in range(0, METADATA_HEADER_SIZE, 4)
    ]
    pairs: List[Tuple[int, int]] = []
    sizes_only = [value for value in fields if value not in offset_candidates]
    for possible_offset in offset_candidates:
        found = False
        pool = fields if possible_offset == 256 else sizes_only
        for size in pool:
            if size == possible_offset or size == 0 or size >= len(metadata) / 3:
                continue
            if size + possible_offset == len(metadata):
                pairs.append((possible_offset, size))
                found = True
                break
            if any(
                possible_offset + size == next_offset and possible_offset != next_offset
                for next_offset in offset_candidates
            ):
                pairs.append((possible_offset, size))
                found = True
                break
        if found:
            continue
        index = offset_candidates.index(possible_offset)
        next_offset = (
            offset_candidates[index + 1] if index + 1 < len(offset_candidates) else None
        )
        is_256 = possible_offset == 256
        is_big_enough = possible_offset > len(metadata) / 3
        is_size_big_enough = (
            next_offset is not None and next_offset - possible_offset > 4096
        )
        did_last_add_up = bool(pairs) and (sum(pairs[-1]) == possible_offset)
        if (is_256 or is_big_enough or is_size_big_enough) and (
            did_last_add_up or is_256 or not pairs
        ):
            size = (
                next_offset - possible_offset
                if next_offset is not None
                else len(metadata) - possible_offset
            )
            pairs.append((possible_offset, size))
            log_info(f"Approximate section at {possible_offset} with size {size}")
        else:
            sizes_only.append(possible_offset)
    return sorted(pairs, key=lambda pair: pair[0])


def parse_entries(data: bytes, struct_sig: str) -> List[Any]:
    step = struct.calcsize(struct_sig)
    scalar = struct_sig == "<I"
    entries: List[Any] = []
    for index in range(0, len(data) - step + 1, step):
        try:
            fields = struct.unpack_from(struct_sig, data, index)
        except struct.error:
            break
        entries.append(fields[0] if scalar else fields)
    return entries


def apply_heuristic(
    spec: tuple, metadata: bytes, offsets_to_sizes: List[Tuple[int, int]]
) -> Tuple[Optional[Tuple[int, int, bytes]], List[Tuple[int, int]]]:
    name, callback, struct_sig, prefer_lowest, marker = spec
    found: List[Tuple[int, int, bytes]] = []
    for offset, size in offsets_to_sizes:
        data = metadata[offset : offset + size]
        if marker and marker in data:
            found.append((offset, size, data))
            break
        if not struct_sig or not callback:
            continue
        entries = parse_entries(data, struct_sig)
        if not entries:
            continue
        if callback(entries):
            found.append((offset, size, data))
    if not found:
        print(paint(i18n.get("heuristic_failed").format(name=name), COLOR_ERROR, True))
        return None, offsets_to_sizes
    found.sort(key=lambda item: item[1], reverse=not prefer_lowest)
    result = found[0]
    remaining = list(offsets_to_sizes)
    if result[:2] in remaining:
        remaining.remove(result[:2])
    print(
        paint(
            i18n.get("found_section").format(name=name, offset=result[0]), COLOR_PRIMARY
        )
    )
    log_debug(f"Found {name} at {result[0]}")
    return result, remaining


def string_literal_cb(entries: List[Any]) -> bool:
    return all(
        entries[index][1] == entries[0][1] + sum(item[0] for item in entries[:index])
        for index in range(1, len(entries))
    )


def events_cb(entries: List[Any]) -> bool:
    wrong = 0
    last_name_index = entries[0][0]
    for name_index, _, add, remove, _, _ in entries:
        if name_index < last_name_index:
            wrong += 1
            if wrong > 256:
                return False
        if add > 1024 or remove > 1024:
            return False
        last_name_index = name_index
    return True


def token_cb_at(index: int, prefix: int) -> Callable[[List[Any]], bool]:
    def callback(entries: List[Any]) -> bool:
        return all(entry[index] & 0xFF000000 == prefix for entry in entries)

    return callback


def ascending_cb(entries: List[Any]) -> bool:
    return all(entries[i][0] <= entries[i + 1][0] for i in range(len(entries) - 1))


def nested_types_cb(entries: List[Any]) -> bool:
    right_count, last_index = 0, 0
    for attempts, index in enumerate(entries, 1):
        if index > last_index:
            right_count += 1
        else:
            right_count -= 1
        if right_count > 256:
            return True
        if right_count < -4 or index > 0x01000000 or attempts > 512:
            return False
        last_index = index
    return True


def interfaces_cb(entries: List[Any]) -> bool:
    return all(256 <= value <= 1024576 for value in entries)


def vtable_methods_cb(entries: List[Any]) -> bool:
    return all(value == 1 or value & 0xE0000000 != 0 for value in entries)


def interface_offsets_cb(entries: List[Any]) -> bool:
    for type_index, offset in entries:
        if offset > 256 or type_index < 256 or type_index > 65535:
            return False
    return True


def type_definitions_cb(entries: List[Any]) -> bool:
    return all(entry[25] & 0xFF000000 == 0x02000000 for entry in entries)


def images_cb(entries: List[Any]) -> bool:
    if len(entries) < 2:
        return False
    return all(entry[7] == 1 for entry in entries[:-2])


def field_refs_cb(entries: List[Any]) -> bool:
    for type_index, field_index in entries:
        if type_index < 256 or field_index > 2048:
            return False
    return True


def referenced_assemblies_cb(entries: List[Any]) -> bool:
    if not entries:
        return True
    mean = sum(entries) / len(entries)
    if not 30 < mean < 40:
        return False
    return all(value <= 256 for value in entries)


def attribute_data_range_cb(entries: List[Any]) -> bool:
    right = 0
    last_index = entries[0][1]
    if last_index != 0:
        return False
    for token, index in entries:
        right += -10 if token & 0xFF000000 == 0 else 2
        right += -2 if index < last_index else 1
        if right > 2048:
            return True
        if right < -16:
            return False
    return True


def unresolved_types_cb(entries: List[Any]) -> bool:
    return all(256 <= value <= 70000 for value in entries)


def unresolved_type_ranges_cb(entries: List[Any]) -> bool:
    expected = entries[0][0]
    for start, length in entries:
        if start != expected:
            return False
        expected += length
    return True


def exported_type_definitions_cb(entries: List[Any]) -> bool:
    return all(64 <= value <= 131072 for value in entries)


def generic_parameters_cb(entries: List[Any]) -> bool:
    expected = entries[0][2]
    for _, name_index, constraints_start, constraints_count, _, _ in entries:
        if constraints_start not in (0, expected) or name_index < 256:
            return False
        expected += constraints_count
    return True


def generic_constraints_cb(entries: List[Any]) -> bool:
    return all(256 <= value <= 1024576 for value in entries)


def generic_containers_cb(entries: List[Any]) -> bool:
    for _, type_argc, is_method, _ in entries:
        if is_method not in (0, 1) or type_argc > 128:
            return False
    return True


def get_heuristics() -> List[tuple]:
    return [
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
        ("properties", token_cb_at(4, 0x17000000), "<IIIII", False, None),
        ("methods", token_cb_at(6, 0x06000000), "<IIIIIIIHHHH", False, None),
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
        ("parameters", token_cb_at(1, 0x08000000), "<III", True, None),
        ("fields", token_cb_at(2, 0x04000000), "<III", True, None),
        ("genericParameters", generic_parameters_cb, "<IIHHHH", True, None),
        ("genericParameterConstraints", generic_constraints_cb, "<I", True, None),
        ("genericContainers", generic_containers_cb, "<IIII", False, None),
        ("nestedTypes", nested_types_cb, "<I", False, None),
        ("interfaces", interfaces_cb, "<I", False, None),
        ("vtableMethods", vtable_methods_cb, "<I", False, None),
        ("interfaceOffsets", interface_offsets_cb, "<II", False, None),
        (
            "typeDefinitions",
            type_definitions_cb,
            "<IIIIIIIIIIIIIIIIHHHHHHHHII",
            False,
            None,
        ),
        ("images", images_cb, "<IIIIIIIIII", False, None),
        ("assemblies", token_cb_at(1, 0x20000000), "<IIIIIIIIIIIIIIII", False, None),
        ("fieldRefs", field_refs_cb, "<II", False, None),
        ("referencedAssemblies", referenced_assemblies_cb, "<I", False, None),
        ("attributeData", None, None, False, b"NewFragmentBox"),
        ("attributeDataRange", attribute_data_range_cb, "<II", False, None),
        (
            "unresolvedIndirectCallParameterTypes",
            unresolved_types_cb,
            "<I",
            False,
            None,
        ),
        (
            "unresolvedIndirectCallParameterTypeRanges",
            unresolved_type_ranges_cb,
            "<II",
            False,
            None,
        ),
        ("exportedTypeDefinitions", exported_type_definitions_cb, "<I", False, None),
    ]


def unshuffle_metadata_header(header: bytes, full_size: int) -> Optional[List[int]]:
    if len(header) < METADATA_HEADER_SIZE:
        return None
    values = list(struct.unpack_from("<64I", header, 0))
    counts: dict = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    candidates = [
        value for value, count in counts.items() if count >= 3 and value > 256
    ]
    if not candidates:
        return None
    highest = max(candidates)
    tail = full_size - highest
    last_size = 0
    for value in values:
        if value % 4 == 0 and abs(tail - value) <= 4:
            last_size = value
            break
    if last_size == 0:
        return None
    pairs: List[Tuple[int, int]] = [(highest, last_size), (highest, 0), (highest, 0)]
    left = SECTION_SLOTS
    current = highest
    for _ in range(SECTION_SLOTS):
        matched = False
        for i in range(len(values)):
            if values[i] <= 0 or values[i] % 4 != 0:
                continue
            for j in range(len(values)):
                if values[j] <= 0:
                    continue
                prev_offset, prev_size = values[j], values[i]
                if len(pairs) in (25, 28, 29, 30):
                    prev_offset, prev_size = (
                        min(prev_offset, prev_size),
                        max(prev_offset, prev_size),
                    )
                else:
                    prev_offset, prev_size = (
                        max(prev_offset, prev_size),
                        min(prev_offset, prev_size),
                    )
                if abs(prev_size - (current - prev_offset)) <= 4:
                    pairs.append((prev_offset, prev_size))
                    current = prev_offset
                    left -= 1
                    values[i] = 0
                    values[j] = 0
                    matched = True
                    break
            if matched:
                break
        if not matched:
            break
    if left != 0:
        return None
    offsets = sorted({offset for offset, _ in pairs})
    if len(offsets) != SECTION_SLOTS + 1 or offsets[0] == 0:
        return None
    return offsets


def build_reconstructed_metadata(metadata: bytes, offsets: Sequence[int]) -> bytes:
    found = list(offsets)
    lookup = sorted(found)
    header = bytearray(
        METADATA_HEADER_MAGIC
        + METADATA_VERSION_STUB
        + METADATA_DATA_OFFSET_STUB
        + b"\x00" * (METADATA_HEADER_SIZE - 12)
    )
    body = bytearray()
    position = 0

    def add(size: int) -> None:
        nonlocal position
        if len(header) < 20 + position:
            return
        struct.pack_into("<I", header, 12 + position, size)
        total = struct.unpack_from("<I", header, 8 + position)[0] + size
        struct.pack_into("<I", header, 16 + position, total)
        position += 8

    for offset in found[:SECTION_SLOTS]:
        index = lookup.index(offset)
        size = (
            lookup[index + 1] - offset
            if index + 1 < len(lookup)
            else len(metadata) - offset
        )
        add(size)
        body += metadata[offset : offset + size]
    for _ in range(SECTION_SLOTS - len(found[:SECTION_SLOTS])):
        add(0)
    add(0)
    add(0)
    if len(found) > SECTION_SLOTS:
        last = found[SECTION_SLOTS]
        last_size = len(metadata) - last
        struct.pack_into("<I", header, 252, last_size)
        body += metadata[last : last + last_size]
    return bytes(header + body)


def decrypt_metadata(
    metadata: bytes,
    output_path: str,
    exclude_offsets: Optional[str] = None,
    skip_decrypt: bool = False,
) -> bool:
    log_info(f"Decrypting metadata to: {output_path}")
    try:
        print(paint(i18n.get("starting_decrypt"), COLOR_SUCCESS))
        if skip_decrypt:
            print(paint(i18n.get("skipping_decryption"), COLOR_PRIMARY))
        else:
            metadata, key = try_decrypt_metadata(metadata)
            if key:
                print(paint(i18n.get("auto_decrypted").format(key=key), COLOR_SUCCESS))
            else:
                print(paint(i18n.get("metadata_unencrypted"), COLOR_PRIMARY))
        version, desc = get_metadata_version(metadata)
        print(
            paint(
                i18n.get("metadata_version").format(version=version, desc=desc),
                COLOR_PRIMARY,
            )
        )
        if version < 15 or version > max(SUPPORTED_VERSIONS):
            print(
                paint(
                    i18n.get("version_unknown").format(version=version), COLOR_WARNING
                )
            )
        elif version > 38:
            print(
                paint(
                    i18n.get("version_limited").format(version=version), COLOR_WARNING
                )
            )
        if len(metadata) < METADATA_HEADER_SIZE:
            print(paint(i18n.get("metadata_too_small"), COLOR_ERROR))
            log_error("Metadata too small for header parsing")
            return False
        if dump_debug:
            try:
                with open(DUMP_FILE, "wb") as handle:
                    handle.write(metadata)
                print(
                    paint(i18n.get("debug_dump").format(path=DUMP_FILE), COLOR_PRIMARY)
                )
            except (IOError, OSError) as error:
                print(paint(i18n.get("dump_failed").format(error=error), COLOR_WARNING))
        offset_candidates = find_offset_candidates(metadata)
        print(
            paint(
                i18n.get("offset_candidates").format(count=len(offset_candidates)),
                COLOR_PRIMARY,
            )
        )
        if exclude_offsets:
            for excluded in exclude_offsets.replace(" ", "").split(","):
                if not excluded:
                    continue
                try:
                    offset_candidates.remove(int(excluded))
                    print(
                        paint(
                            i18n.get("excluded_offset").format(value=excluded),
                            COLOR_PRIMARY,
                        )
                    )
                except ValueError:
                    print(
                        paint(
                            i18n.get("offset_not_candidate").format(value=excluded),
                            COLOR_WARNING,
                        )
                    )
        pairs = build_offsets_to_sizes(metadata, offset_candidates)
        print(
            paint(
                i18n.get("validated_pairs")
                + str(len(pairs))
                + i18n.get("offset_size_pairs"),
                COLOR_PRIMARY,
            )
        )
        reconstructed_offsets: List[int] = []
        progress = tqdm(
            get_heuristics(),
            desc="heuristics",
            colour="green",
            unit="section",
            leave=False,
        )
        for spec in progress:
            progress.set_description(spec[0])
            result, pairs = apply_heuristic(spec, metadata, pairs)
            if result:
                reconstructed_offsets.append(result[0])
        if len(reconstructed_offsets) < SECTION_SLOTS + 1:
            print(
                paint(
                    i18n.get("heuristics_insufficient")
                    + f" {len(reconstructed_offsets)} "
                    + i18n.get("trying_unshuffle"),
                    COLOR_WARNING,
                )
            )
            unshuffled = unshuffle_metadata_header(
                metadata[:METADATA_HEADER_SIZE], len(metadata)
            )
            if unshuffled:
                reconstructed_offsets = unshuffled
                print(paint(i18n.get("unshuffle_success"), COLOR_SUCCESS))
            else:
                print(paint(i18n.get("unshuffle_failed"), COLOR_WARNING))
        if len(reconstructed_offsets) < SECTION_SLOTS + 1:
            print(
                paint(
                    i18n.get("warning_sections")
                    + f" {len(reconstructed_offsets)} "
                    + i18n.get("expected_sections"),
                    COLOR_WARNING,
                )
            )
        reconstructed = build_reconstructed_metadata(metadata, reconstructed_offsets)
        written = write_output(reconstructed, output_path, RECONSTRUCTED_NAME)
        print(paint(i18n.get("output") + written, COLOR_ACCENT, True))
        print(
            paint(
                i18n.get("output_size").format(size=len(reconstructed)),
                COLOR_PRIMARY,
            )
        )
        print(paint(i18n.get("decrypt_success"), COLOR_SUCCESS))
        log_info(f"Decrypted to {written}, {len(reconstructed)} bytes")
        return True
    except (IOError, OSError, struct.error, ValueError, IndexError) as error:
        print(paint(f"{i18n.get('error')}{error}", COLOR_ERROR))
        log_error(f"Decrypt error: {error}")
        return False


def show_metadata_info(path: str) -> None:
    try:
        with open(path, "rb") as handle:
            data = handle.read(PROBE_SIZE)
        box_top()
        box_title(i18n.get("metadata_info_title"))
        print(f"{i18n.get('magic')}{data[:4].hex().upper()}")
        version, desc = get_metadata_version(data)
        print(f"{i18n.get('version')}{version} ({desc})")
        print(f"{i18n.get('file_size')}{os.path.getsize(path)} bytes")
        if data[:4] != METADATA_MAGIC:
            print(paint(i18n.get("warning_invalid_magic"), COLOR_WARNING))
        _, key = try_decrypt_metadata(data)
        if key:
            print(paint(i18n.get("possible_encryption") + key, COLOR_SUCCESS))
    except (IOError, OSError) as error:
        print(paint(f"{i18n.get('error')}{error}", COLOR_ERROR))
        log_error(f"Info error: {error}")


def print_menu() -> None:
    print()
    print(paint(f"┌{'─' * MENU_WIDTH}┐", COLOR_PRIMARY))
    items = (
        (COLOR_SUCCESS, "1", i18n.get("menu_extract")),
        (COLOR_SUCCESS, "2", i18n.get("menu_decrypt")),
        (COLOR_SUCCESS, "3", i18n.get("menu_info")),
        (COLOR_WARNING, "4", i18n.get("menu_switch_lang")),
        (COLOR_ERROR, "0", i18n.get("menu_exit")),
    )
    for color, key, label in items:
        line = f"  {key}. {label}"[:MENU_WIDTH].ljust(MENU_WIDTH)
        line = line.replace(key, f"{color}{key}{Style.RESET_ALL}", 1)
        print(paint(f"│{line}│", COLOR_PRIMARY))
    print(paint(f"└{'─' * MENU_WIDTH}┘", COLOR_PRIMARY))


def menu_extract() -> None:
    clear_screen()
    box_top()
    box_title(i18n.get("extract_title"))
    libunity = select_file(
        i18n.get("select_libunity"), [("SO files", ".so"), ("All files", ".*")]
    )
    if not libunity:
        print(paint(i18n.get("no_file_selected"), COLOR_ERROR))
        return
    print(f"{i18n.get('libunity')}{libunity}")
    output = select_save_file(
        i18n.get("save_metadata"),
        [("DAT files", ".dat"), ("All files", ".*")],
        ".dat",
    )
    if not output:
        print(paint(i18n.get("no_output_path"), COLOR_ERROR))
        return
    entered = prompt(i18n.get("max_size"))
    try:
        size = int(entered) if entered else DEFAULT_MAX_SIZE
    except ValueError:
        size = DEFAULT_MAX_SIZE
    result = extract_metadata(libunity, size)
    if not result:
        return
    metadata, _ = result
    try:
        written = write_output(metadata, output, EXTRACTED_NAME)
        print(paint(i18n.get("extracted_to") + written, COLOR_SUCCESS))
    except (IOError, OSError) as error:
        print(paint(f"{i18n.get('error')}{error}", COLOR_ERROR))
        log_error(f"Write error: {error}")


def menu_decrypt() -> None:
    clear_screen()
    box_top()
    box_title(i18n.get("decrypt_title"))
    input_file = select_file(
        i18n.get("select_encrypted"), [("DAT files", ".dat"), ("All files", ".*")]
    )
    if not input_file:
        print(paint(i18n.get("no_file_selected"), COLOR_ERROR))
        return
    print(f"{i18n.get('input')}{input_file}")
    output = select_save_file(
        i18n.get("save_decrypted"),
        [("DAT files", ".dat"), ("All files", ".*")],
        ".dat",
    )
    if not output:
        print(paint(i18n.get("no_output_path"), COLOR_ERROR))
        return
    exclude = prompt(i18n.get("exclude_offsets_prompt")) or None
    skip = (prompt(i18n.get("skip_decrypt_prompt")) or "").lower() in ("y", "yes")
    try:
        with open(input_file, "rb") as handle:
            metadata = handle.read()
    except (IOError, OSError) as error:
        print(paint(f"{i18n.get('error')}{error}", COLOR_ERROR))
        log_error(f"Read error: {error}")
        return
    decrypt_metadata(metadata, output, exclude, skip_decrypt=skip)


def menu_info() -> None:
    clear_screen()
    box_top()
    box_title(i18n.get("info_title"))
    input_file = select_file(
        i18n.get("select_metadata"), [("DAT files", ".dat"), ("All files", ".*")]
    )
    if not input_file:
        print(paint(i18n.get("no_file_selected"), COLOR_ERROR))
        return
    print(f"{i18n.get('file')}{input_file}")
    show_metadata_info(input_file)


def interactive_menu() -> None:
    clear_screen()
    print(paint(i18n.BANNER, COLOR_PRIMARY))
    while True:
        print_menu()
        choice = prompt(f"{i18n.get('select_option')}: ")
        if choice is None:
            print(paint(i18n.get("exiting"), COLOR_SUCCESS))
            break
        if choice == "1":
            menu_extract()
        elif choice == "2":
            menu_decrypt()
        elif choice == "3":
            menu_info()
        elif choice == "4":
            config["language"] = i18n.toggle_language()
            save_config()
            print(
                paint(
                    i18n.get("lang_changed") + config["language"].upper(), COLOR_SUCCESS
                )
            )
        elif choice == "0":
            print(paint(i18n.get("exiting"), COLOR_SUCCESS))
            log_info("Application exited")
            break
        else:
            print(paint(i18n.get("invalid_option"), COLOR_ERROR))
        if prompt(f"\n{i18n.get('press_enter')}") is None:
            break
        clear_screen()
        print(paint(i18n.BANNER, COLOR_PRIMARY))
    log_info("Application exited")


def load_dependencies() -> None:
    global Style, tqdm, ELFTOOLS_AVAILABLE, ELFFile
    ensure_dependency("colorama")
    ensure_dependency("tqdm")
    ensure_dependency("pyelftools", "elftools")
    from colorama import Style as colorama_style
    from colorama import init as colorama_init
    from tqdm import tqdm as tqdm_module

    Style = colorama_style
    tqdm = tqdm_module
    colorama_init(autoreset=False)
    try:
        from elftools.elf.elffile import ELFFile as elf_file_class

        ELFFile = elf_file_class
        ELFTOOLS_AVAILABLE = True
    except ImportError:
        ELFTOOLS_AVAILABLE = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Metadata-Worker",
        description="IL2CPP Metadata Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "commands:\n"
            "  extract   pull the metadata blob out of libunity.so\n"
            "  decrypt   rebuild a valid header for a dumped metadata blob\n"
            "  info      show magic, version and size of a metadata file\n"
            "  menu      interactive menu (default)\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"Metadata-Worker {VERSION}"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    extract_parser = subparsers.add_parser(
        "extract", help="Extract metadata from libunity.so"
    )
    extract_parser.add_argument("libunity", help="Path to libunity.so")
    extract_parser.add_argument("-o", "--output", required=True, help="Output path")
    extract_parser.add_argument(
        "-s", "--size", type=int, default=DEFAULT_MAX_SIZE, help="Max extraction size"
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt extracted metadata")
    decrypt_parser.add_argument("input", help="Path to encrypted metadata")
    decrypt_parser.add_argument("-o", "--output", required=True, help="Output path")
    decrypt_parser.add_argument("-e", "--exclude", help="Exclude offsets (e.g. 1,2,3)")
    decrypt_parser.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Skip auto-decryption, only heuristic reconstruction",
    )
    decrypt_parser.add_argument(
        "--no-dump", action="store_true", help="Do not write the debug metadata dump"
    )

    info_parser = subparsers.add_parser("info", help="Show metadata info")
    info_parser.add_argument("input", help="Path to metadata file")

    subparsers.add_parser("menu", help="Interactive menu mode")
    return parser


def require_file(path: str) -> None:
    if not os.path.isfile(path):
        print(paint(f"{i18n.get('error')}{path} not found", COLOR_ERROR))
        log_error(f"File not found: {path}")
        sys.exit(1)


def run_extract(args: argparse.Namespace) -> None:
    require_file(args.libunity)
    result = extract_metadata(args.libunity, args.size)
    if not result:
        sys.exit(1)
    metadata, _ = result
    written = write_output(metadata, args.output, EXTRACTED_NAME)
    print(paint(i18n.get("extracted_to") + written, COLOR_SUCCESS))


def run_decrypt(args: argparse.Namespace) -> None:
    require_file(args.input)
    with open(args.input, "rb") as handle:
        metadata = handle.read()
    if not decrypt_metadata(
        metadata, args.output, args.exclude, skip_decrypt=args.no_decrypt
    ):
        sys.exit(1)


def run_info(args: argparse.Namespace) -> None:
    require_file(args.input)
    show_metadata_info(args.input)


def configure_streams() -> None:
    for name in ("stdout", "stderr"):
        stream: Any = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main() -> None:
    global dump_debug
    configure_streams()
    args = build_parser().parse_args()
    load_dependencies()
    setup_logging()
    load_config()
    log_info(f"Application started, version {VERSION}")
    if not args.command or args.command == "menu":
        interactive_menu()
        return
    dump_debug = not getattr(args, "no_dump", False)
    print(paint(i18n.BANNER, COLOR_PRIMARY))
    with loading(args.command):
        if args.command == "extract":
            run_extract(args)
        elif args.command == "decrypt":
            run_decrypt(args)
        elif args.command == "info":
            run_info(args)
    log_info("Command finished")


if __name__ == "__main__":
    main()
