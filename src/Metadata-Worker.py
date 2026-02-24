import argparse
import collections
import os
import struct
import sys
import time
import zipfile
from typing import Optional, Tuple, List, Callable, Any
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

if getattr(sys, 'frozen', False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import i18n

colorama_init(autoreset=True)

BANNER = i18n.get("banner")

FRIDA_SCRIPT_TEMPLATE = """Interceptor.attach(Module.findExportByName(null, 'dlopen'), {{
    onEnter: function(args) {{
        this.path = args[0].readUtf8String();
    }},
    onLeave: function(retval) {{
        if(this.path.indexOf('libil2cpp.so') !== -1) {{
            var il2cpp = Module.findBaseAddress('libil2cpp.so');
            console.error('[!] il2cpp : ' + il2cpp);
            var LoadMetaDataFile = il2cpp.add({offset});
            Interceptor.attach(LoadMetaDataFile, {{
                onLeave: function(retval) {{
                    console.error('[!] LoadMetaDataFile retval : ' + retval);
                }}
            }});
        }}
    }}
}});
"""

FRIDA_MEMORY_DUMP_SCRIPT = """
let metadataSize = 0;
let metadataPtr = 0;

function findPattern(pattern) {{
    const patternBytes = pattern.split(' ').map(b => b === '?' ? null : parseInt(b, 16));
    const ranges = Process.enumerateRanges('r--');
    for (const range of ranges) {{
        try {{
            const memory = Memory.readByteArray(range.base, range.size);
            if (!memory) continue;
            const bytes = new Uint8Array(memory);
            for (let i = 0; i <= bytes.length - patternBytes.length; i++) {{
                let match = true;
                for (let j = 0; j < patternBytes.length; j++) {{
                    if (patternBytes[j] !== null && bytes[i + j] !== patternBytes[j]) {{
                        match = false;
                        break;
                    }}
                }}
                if (match) {{
                    return range.base.add(i);
                }}
            }}
        }} catch (e) {{}}
    }}
    return null;
}}

function dumpMetadata(ptr, size, packageName) {{
    const path = `/data/local/tmp/${{packageName}}_global-metadata.dat`;
    const file = new File(path, 'wb');
    file.write(Memory.readByteArray(ptr, size));
    file.flush();
    file.close();
    console.log(`[+] Dumped to ${{path}}`);
    console.log(`[+] Size: ${{size}} bytes`);
}}

rpc.exports = {{
    start: function(offset, size, pattern, packageName) {{
        console.log('[*] Starting metadata dump...');

        if (offset) {{
            const func = Module.getBaseAddress('libil2cpp.so').add(offset);
            try {{
                const ret = new NativeFunction(func, 'pointer', []);
                metadataPtr = ret();
                metadataSize = size || 0;
                console.log(`[*] Using offset: 0x${{offset.toString(16)}}`);
            }} catch (e) {{
                console.error(`[-] Failed to call function at offset: ${{e}}`);
                return;
            }}
        }} else {{
            const scan = findPattern(pattern || "af 1b b1 fa 1? 00 00 00 00");
            if (scan) {{
                metadataPtr = scan.readPointer();
                metadataSize = size || 0;
                console.log(`[*] Found metadata pointer at: ${{scan}}`);
            }} else {{
                console.error('[-] Metadata not found via pattern scan');
                return;
            }}
        }}

        if (metadataPtr.isNull()) {{
            console.error('[-] Metadata pointer is null');
            return;
        }}

        if (metadataSize === 0) {{
            metadataSize = metadataPtr.readU32();
            console.log(`[*] Detected metadata size: ${{metadataSize}}`);
        }}

        dumpMetadata(metadataPtr, metadataSize, packageName);
    }}
}};
"""

METADATA_MAGIC = b"\xaf\x1b\xb1\xfa"
METADATA_MARKER_64 = b"\x15\x00\x0c\x0c\x10\x1b\x23\x00\x00\x00\x00\x00\x28\x00\x2c\x10"
METADATA_MARKER_32 = b"\x00\x01\x01\x02\x01\x02\x02\x03"
METADATA_SIGNATURE = b"\x02\x00\x00\x00\x7c\x00\x00\x06\x0b\x00\x00\x00\x02\x00\x00\x00"
METADATA_HEADER_MAGIC = b"\xaf\x1b\xb1\xfa\x1f\x00\x00\x00\x00\x01\x00\x00"

SUPPORTED_VERSIONS = {
    15: "Unity 2015",
    16: "Unity 2017",
    17: "Unity 2017.1",
    18: "Unity 2017.2",
    19: "Unity 2017.3",
    20: "Unity 2017.4",
    21: "Unity 2018",
    22: "Unity 2018.2",
    23: "Unity 2018.3",
    24: "Unity 2019-2021",
    25: "Unity 2019.3",
    26: "Unity 2020",
    27: "Unity 2020.2",
    28: "Unity 2020.3",
    29: "Unity 2021",
    30: "Unity 2022",
    31: "Unity 2022.2",
    32: "Unity 2023",
    33: "Unity 2023.1",
    34: "Unity 2023.2",
    35: "Unity 2024",
    36: "Unity 2024.1",
    37: "Unity 2024.2",
    38: "Unity 2024.3",
    39: "Unity 2025 (experimental)",
    40: "Unity 2025.1 (experimental)",
    41: "Unity 2025.2 (experimental)",
    42: "Unity 2025.3 (experimental)",
    43: "Unity 2026+ (experimental)",
}

COMMON_XOR_KEYS = [
    [0x77, 0x61, 0x6E, 0x7A, 0x67],
    [0x77, 0x61, 0x6E, 0x27, 0x7A, 0x67],
    [0xAA],
    [0x5A],
    [0x0A],
    [0xFF],
    [0x00, 0x00, 0x00, 0x00],
    [0x12, 0x34, 0x56, 0x78],
    [0xDE, 0xAD, 0xBE, 0xEF],
    [0xE6, 0x68, 0xE9, 0x05],
    [0xE6, 0x68, 0xE9, 0x05, 0xBC, 0xA7, 0x4E, 0xDB],
    [0x49, 0x73, 0x58, 0xFF],
]


def validate_path(path: str, must_exist: bool = True) -> Optional[str]:
    try:
        p = Path(path).resolve()
        if must_exist and not p.exists():
            return None
        return str(p)
    except (ValueError, OSError):
        return None


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def select_file_cli(title: str) -> str:
    print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    while True:
        try:
            path = input(i18n.get("path_to_file")).strip()
        except EOFError:
            return ""
        if path.lower() == 'q':
            return ""
        if os.path.isfile(path):
            return path
        print(f"{Fore.RED}{i18n.get('file_not_found')}{Style.RESET_ALL}")


def select_save_file_cli(title: str, defaultextension: str = "") -> str:
    print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    while True:
        try:
            path = input(i18n.get("path_to_save")).strip()
        except EOFError:
            return ""
        if path.lower() == 'q':
            return ""
        if path:
            if defaultextension and not path.endswith(defaultextension):
                path += defaultextension
            return path
        print(f"{Fore.RED}{i18n.get('enter_path')}{Style.RESET_ALL}")


def select_folder_cli(title: str) -> str:
    print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    while True:
        try:
            path = input(i18n.get("path_to_folder")).strip()
        except EOFError:
            return ""
        if path.lower() == 'q':
            return ""
        if os.path.isdir(path):
            return path
        print(f"{Fore.RED}{i18n.get('folder_not_found')}{Style.RESET_ALL}")


def select_file(title: str, filetypes: list) -> str:
    if TKINTER_AVAILABLE:
        root = None
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
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
            file_path = filedialog.asksaveasfilename(title=title, filetypes=filetypes, defaultextension=defaultextension)
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
        print(f"{i18n.get('running')}{frame}", end="\r")
        time.sleep(0.1)
    print(f"{i18n.get('loading_complete')}     ")


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
            v[1] = (v[1] - (((v[0] << 4) + v[0]) ^ (v[0] + sum_val) ^ ((v[0] >> 5) + key[(sum_val >> 11) & (key_idx - 1)]))) & 0xFFFFFFFF
            v[0] = (v[0] - (((v[1] << 4) + v[1]) ^ (v[1] + sum_val) ^ ((v[1] >> 5) + key[sum_val & (key_idx - 1)]))) & 0xFFFFFFFF
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


def compare_metadata_files(file1: str, file2: str, bytes_count: int = 10) -> bool:
    if not os.path.isfile(file1):
        print(f"{Fore.RED}{i18n.get('file_not_exist')}{file1}{i18n.get('does_not_exist')}{Style.RESET_ALL}")
        return False
    if not os.path.isfile(file2):
        print(f"{Fore.RED}{i18n.get('file_not_exist')}{file2}{i18n.get('does_not_exist')}{Style.RESET_ALL}")
        return False

    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        data1 = f1.read(bytes_count)
        data2 = f2.read(bytes_count)

    print(f"\n{Fore.CYAN}{i18n.get('bytes_hex')}{file1}:{Style.RESET_ALL} " + " ".join(f"{b:02x}" for b in data1))
    print(f"{Fore.CYAN}{i18n.get('bytes_hex')}{file2}:{Style.RESET_ALL} " + " ".join(f"{b:02x}" for b in data2))

    with open(file1, "rb") as f1:
        full1 = f1.read(8)
    with open(file2, "rb") as f2:
        full2 = f2.read(8)

    v1, desc1 = get_metadata_version(full1) if full1[:4] == METADATA_MAGIC else (-1, "Invalid")
    v2, desc2 = get_metadata_version(full2) if full2[:4] == METADATA_MAGIC else (-1, "Invalid")
    print(f"\n{Fore.CYAN}{file1}: Version {v1} ({desc1}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{file2}: Version {v2} ({desc2}){Style.RESET_ALL}")

    if data1 == data2:
        print(f"{Fore.GREEN}{i18n.get('bytes_identical')}{bytes_count}{i18n.get('bytes_identical_end')}{Style.RESET_ALL}")
        return True
    else:
        different = [i + 1 for i in range(bytes_count) if data1[i] != data2[i]]
        print(f"{Fore.YELLOW}{i18n.get('bytes_different')}{different}{i18n.get('are_different')}{different}{Style.RESET_ALL}")
        return False


def generate_frida_script(offset: str, output_path: Optional[str] = None) -> str:
    if not offset.startswith("0x"):
        offset = f"0x{offset}"
    script = FRIDA_SCRIPT_TEMPLATE.format(offset=offset)
    if output_path:
        with open(output_path, "w") as f:
            f.write(script)
        print(f"{Fore.GREEN}Frida script saved to {output_path}{Style.RESET_ALL}")
    return script


def generate_frida_memory_dump_script(output_path: Optional[str] = None) -> str:
    script = FRIDA_MEMORY_DUMP_SCRIPT
    if output_path:
        with open(output_path, "w") as f:
            f.write(script)
        print(f"{Fore.GREEN}Frida memory dump script saved to {output_path}{Style.RESET_ALL}")
    return script


def find_metadata_in_libunity(libunity_path: str) -> Optional[int]:
    with open(libunity_path, "rb") as f:
        data = f.read()
    idx = data.find(METADATA_MAGIC)
    if idx != -1:
        print(
            f"{Fore.GREEN}Found embedded metadata at offset {hex(idx)}{Style.RESET_ALL}"
        )
        return idx
    return None


def find_metadata_in_apk(apk_path: str) -> Optional[Tuple[str, int]]:
    try:
        with zipfile.ZipFile(apk_path, "r") as apk:
            for name in apk.namelist():
                if "metadata" in name.lower() and name.endswith(".dat"):
                    info = apk.getinfo(name)
                    print(
                        f"{Fore.GREEN}Found metadata in APK: {name} ({info.file_size} bytes){Style.RESET_ALL}"
                    )
                    return name, info.file_size
    except zipfile.BadZipFile:
        print(f"{Fore.RED}Error: Invalid APK file{Style.RESET_ALL}")
    except (IOError, OSError) as e:
        print(f"{Fore.RED}Error reading APK: {e}{Style.RESET_ALL}")
    return None


def find_metadata_in_folder(folder_path: str) -> Optional[Tuple[str, int]]:
    metadata_paths = [
        os.path.join(folder_path, "assets", "bin", "Data", "Managed", "Metadata", "global-metadata.dat"),
        os.path.join(folder_path, "assets", "bin", "Data", "Managed", "global-metadata.dat"),
        os.path.join(folder_path, "assets", "il2cpp_data", "Metadata", "global-metadata.dat"),
        os.path.join(folder_path, "assets", "global-metadata.dat"),
        os.path.join(folder_path, "global-metadata.dat"),
    ]
    for path in metadata_paths:
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                print(f"{Fore.GREEN}Found metadata in folder: {path} ({size} bytes){Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}Found metadata: {path} ({size} bytes){Style.RESET_ALL}")
                    return path, size
                except (IOError, OSError):
                    continue

    return None


def extract_from_apk(input_path: str, output_path: str, force: bool = False) -> bool:
    try:
        is_folder = os.path.isdir(input_path)
        is_apk = os.path.isfile(input_path) and input_path.lower().endswith(".apk")

        if not is_folder and not is_apk:
            print(f"{Fore.RED}Error: {input_path} is not a valid APK file or folder{Style.RESET_ALL}")
            return False

        data = None
        if is_apk:
            result = find_metadata_in_apk(input_path)
            if not result:
                print(f"{Fore.YELLOW}No metadata found in APK{Style.RESET_ALL}")
                return False
            try:
                with zipfile.ZipFile(input_path, "r") as apk:
                    data = apk.read(result[0])
            except zipfile.BadZipFile:
                print(f"{Fore.RED}Error: Invalid APK file{Style.RESET_ALL}")
                return False
        else:
            result = find_metadata_in_folder(input_path)
            if not result:
                print(f"{Fore.YELLOW}No metadata found in folder{Style.RESET_ALL}")
                return False
            with open(result[0], "rb") as f:
                data = f.read()

        data, key = try_decrypt_metadata(data)
        if key:
            print(f"{Fore.GREEN}Auto-decrypted: {key}{Style.RESET_ALL}")
        elif not force and data[:4] != METADATA_MAGIC:
            print(f"{Fore.YELLOW}Metadata appears encrypted. Use --force to extract anyway.{Style.RESET_ALL}")
            version, desc = get_metadata_version(data)
            print(f"{Fore.CYAN}Version detected: {version} ({desc}){Style.RESET_ALL}")
            return False

        with open(output_path, "wb") as f:
            f.write(data)
        print(f"{Fore.GREEN}Metadata extracted to {output_path}{Style.RESET_ALL}")
        return True
    except (IOError, OSError, zipfile.BadZipFile) as e:
        print(f"{Fore.RED}Error extracting from APK: {e}{Style.RESET_ALL}")
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
                print(f"{Fore.RED}Error: .data section not found.{Style.RESET_ALL}")
                return None

            print(f"{Fore.CYAN}Collecting relocations...{Style.RESET_ALL}")
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
                    if not (data_section["sh_addr"] <= addr < data_section["sh_addr"] + data_section["sh_size"]):
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

            print(f"{Fore.CYAN}Searching for metadata pointer...{Style.RESET_ALL}")
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
            print(f"{Fore.YELLOW}Warning: No metadata pointer found via relocations, trying alternative method...{Style.RESET_ALL}")
            return extract_metadata_pointer_alternative(libunity_path)
        elif len(candidates) > 1:
            print(
                f"{Fore.YELLOW}Multiple candidates found, using first: {hex(candidates[0])}{Style.RESET_ALL}"
            )

        return candidates[0]
    except Exception as e:
        print(f"{Fore.RED}Error extracting metadata pointer: {e}{Style.RESET_ALL}")
        return None


def extract_metadata_pointer_alternative(libunity_path: str) -> Optional[int]:
    try:
        with open(libunity_path, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        print(f"{Fore.RED}Error reading libunity.so: {e}{Style.RESET_ALL}")
        return None

    print(f"{Fore.CYAN}Scanning for metadata magic bytes...{Style.RESET_ALL}")
    idx = data.find(METADATA_MAGIC)
    if idx != -1:
        print(f"{Fore.GREEN}Found metadata at offset: {hex(idx)}{Style.RESET_ALL}")
        return idx

    print(f"{Fore.CYAN}Scanning for metadata signature...{Style.RESET_ALL}")
    idx = data.find(METADATA_SIGNATURE)
    if idx != -1:
        print(f"{Fore.GREEN}Found metadata signature at offset: {hex(idx)}{Style.RESET_ALL}")
        return idx

    print(f"{Fore.RED}Error: No metadata found in libunity.so{Style.RESET_ALL}")
    return None


def extract_metadata(libunity_path: str, size: int = 30_000_000) -> Optional[Tuple[bytes, bool]]:
    try:
        embedded_offset = find_metadata_in_libunity(libunity_path)
        if embedded_offset is not None:
            with open(libunity_path, "rb") as f:
                f.seek(embedded_offset)
                metadata = f.read(size)
            metadata, key = try_decrypt_metadata(metadata)
            if key:
                print(f"{Fore.GREEN}Auto-decrypted: {key}{Style.RESET_ALL}")
            version, desc = get_metadata_version(metadata)
            print(f"{Fore.CYAN}Metadata version: {version} ({desc}){Style.RESET_ALL}")
            return metadata, True

        metadataptr = extract_metadata_pointer(libunity_path)
        if metadataptr is None:
            return None

        with open(libunity_path, "rb") as libunity:
            libunity.seek(metadataptr)
            metadata = libunity.read(size)

        metadata, key = try_decrypt_metadata(metadata)
        if key:
            print(f"{Fore.GREEN}Auto-decrypted: {key}{Style.RESET_ALL}")

        is64bit = True
        index = metadata.find(METADATA_MARKER_64)
        if index == -1:
            index = metadata.find(METADATA_MARKER_32)
            is64bit = False

        if index != -1:
            index += (4 - index % 4) % 4
            if index > 0 and index <= len(metadata):
                metadata = metadata[:index]
            print(f"{Fore.GREEN}Metadata end marker found ({'64-bit' if is64bit else '32-bit'}).{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Warning: End marker not found, using full dump.{Style.RESET_ALL}")

        version, desc = get_metadata_version(metadata)
        print(f"{Fore.CYAN}Metadata version: {version} ({desc}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}Metadata size: {len(metadata)} bytes{Style.RESET_ALL}")
        return metadata, is64bit
    except (IOError, OSError, struct.error) as e:
        print(f"{Fore.RED}Error extracting metadata: {e}{Style.RESET_ALL}")
        return None


def find_offset_candidates(metadata: bytes) -> List[int]:
    fields = []
    for i in range(0, 256, 4):
        value = struct.unpack("<I", metadata[i:i+4])[0]
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

        behind = metadata[field-4096:field]
        ahead = metadata[field:field+4096]
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

    for offset, size in offsets_to_sizes:
        data = metadata[offset:offset+size]
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
                entries.append(fields[0] if len(struct_sig.rstrip('x')) <= 1 else fields)
            except struct.error:
                break

        if callback and callback(entries):
            found.append((offset, size, data))

    if not found:
        print(f"{Fore.RED + Style.BRIGHT}Failed heuristic: {name}{Style.RESET_ALL}")
        return None, offsets_to_sizes

    found.sort(key=lambda x: x[1], reverse=not prefer_lowest)
    result = found[0]
    if result[:2] in remaining:
        remaining.remove(result[:2])
    print(f"{Fore.CYAN}Found {name} at offset {result[0]}{Style.RESET_ALL}")
    return result, remaining


def decrypt_metadata(metadata: bytes, output_path: str) -> bool:
    try:
        print(f"{Fore.GREEN}Starting metadata decryption...{Style.RESET_ALL}")

        metadata, key = try_decrypt_metadata(metadata)
        if key:
            print(f"{Fore.GREEN}Auto-decrypted: {key}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}Metadata is not encrypted or uses unknown encryption{Style.RESET_ALL}")

        version, desc = get_metadata_version(metadata)
        print(f"{Fore.CYAN}Metadata version: {version} ({desc}){Style.RESET_ALL}")

        if version < 15 or version > 43:
            print(f"{Fore.YELLOW}Warning: Unknown metadata version {version}{Style.RESET_ALL}")
        elif version > 38:
            print(f"{Fore.YELLOW}Warning: Version {version} may have limited support{Style.RESET_ALL}")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        debug_path = os.path.join(script_dir, "debug-metadata.bin")
        with open(debug_path, "wb") as f:
            f.write(metadata)
        print(f"{Fore.CYAN}Debug dump saved to {debug_path}{Style.RESET_ALL}")

        offset_candidates = find_offset_candidates(metadata)
        print(
            f"{Fore.CYAN}Found {len(offset_candidates)} offset candidates{Style.RESET_ALL}"
        )

        offsets_to_sizes: List[Tuple[int, int]] = []
        only_sizes = [x for x in [struct.unpack("<I", metadata[i:i+4])[0] for i in range(0, 256, 4)] if x not in offset_candidates]

        for offset in offset_candidates:
            search_pool = only_sizes if offset != 256 else [struct.unpack("<I", metadata[i:i+4])[0] for i in range(0, 256, 4)]
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
            f"{Fore.CYAN}Validated {len(offsets_to_sizes)} offset/size pairs{Style.RESET_ALL}"
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
                all((x[-1] & 0xFF000000) == prefix for x in e if len(x) > 0) if e else True
            )

        def ascending_cb(e):
            return all(e[i][0] <= e[i + 1][0] for i in range(len(e) - 1)) if e else True

        heuristics = [
            ("stringLiteral", string_literal_cb, "<II", True, None),
            ("stringLiteralData", None, None, True, b"\x00\x00\x00\x01\x09\x00\x00\x01"),
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

        for h_name, h_cb, h_sig, h_pref, h_marker in heuristics:
            result, offsets_to_sizes = apply_heuristic(h_name, offsets_to_sizes, metadata, h_cb, h_sig, h_pref, h_marker)
            if result:
                reconstructed_offsets.append(result[0])

        if len(reconstructed_offsets) < 28:
            print(f"{Fore.YELLOW}Warning: Only found {len(reconstructed_offsets)} sections (expected 29){Style.RESET_ALL}")

        pos = 0

        def add_header_size(size):
            nonlocal pos
            if len(reconstructed) >= 20 + pos:
                reconstructed[12+pos:16+pos] = struct.pack("<I", size)
                new_total = struct.unpack("<I", reconstructed[8+pos:12+pos])[0] + size
                reconstructed[16+pos:20+pos] = struct.pack("<I", new_total)
                pos += 8

        offset_lookup = sorted(reconstructed_offsets)
        for i in range(28):
            if i < len(reconstructed_offsets):
                offset = reconstructed_offsets[i]
                try:
                    idx = offset_lookup.index(offset)
                    size = offset_lookup[idx+1] - offset if idx+1 < len(offset_lookup) else len(metadata) - offset
                except (ValueError, IndexError):
                    size = len(metadata) - offset
                add_header_size(size)
                reconstructed += metadata[offset:offset+size]

        if len(reconstructed) >= 256:
            reconstructed[252:256] = struct.pack(
                "<I", len(metadata) - struct.unpack("<I", reconstructed[248:252])[0]
            )

        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, "output-metadata.dat")

        with open(output_path, "wb") as f:
            f.write(reconstructed)

        print(f"{Fore.MAGENTA + Style.BRIGHT}Output: {output_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Metadata decrypted successfully!{Style.RESET_ALL}")
        return True
    except (IOError, OSError, struct.error) as e:
        print(f"{Fore.RED}Error decrypting metadata: {e}{Style.RESET_ALL}")
        return False


def print_menu():
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}1{Style.RESET_ALL}. {i18n.get('menu_compare')}")
    print(f"  {Fore.GREEN}2{Style.RESET_ALL}. {i18n.get('menu_frida')}")
    print(f"  {Fore.GREEN}3{Style.RESET_ALL}. {i18n.get('menu_extract')}")
    print(f"  {Fore.GREEN}4{Style.RESET_ALL}. {i18n.get('menu_decrypt')}")
    print(f"  {Fore.GREEN}5{Style.RESET_ALL}. {i18n.get('menu_info')}")
    print(f"  {Fore.GREEN}6{Style.RESET_ALL}. {i18n.get('menu_apk')}")
    print(f"  {Fore.GREEN}7{Style.RESET_ALL}. {i18n.get('menu_frida_dump')}")
    print(f"  {Fore.YELLOW}8{Style.RESET_ALL}. {i18n.get('menu_switch_lang')}")
    print(f"  {Fore.RED}0{Style.RESET_ALL}. {i18n.get('menu_exit')}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")


def menu_compare():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('compare_title')} ==={Style.RESET_ALL}")
    file1 = select_file(i18n.get("select_first_file"), [("DAT files", "*.dat"), ("All files", "*.*")])
    if not file1:
        print(f"{Fore.RED}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('first_file')}{file1}")
    file2 = select_file(i18n.get("select_second_file"), [("DAT files", "*.dat"), ("All files", "*.*")])
    if not file2:
        print(f"{Fore.RED}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('second_file')}{file2}")
    try:
        bytes_count = input(i18n.get("bytes_to_compare")).strip()
        bytes_count = int(bytes_count) if bytes_count else 10
    except (EOFError, ValueError):
        bytes_count = 10
    compare_metadata_files(file1, file2, bytes_count)


def menu_frida():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('frida_title')} ==={Style.RESET_ALL}")
    try:
        offset = input(i18n.get("offset_prompt")).strip()
    except EOFError:
        return
    output = select_save_file(i18n.get("save_frida"), [("JS files", "*.js"), ("All files", "*.*")], ".js")
    if not output:
        output = "frida.js"
    generate_frida_script(offset, output)


def menu_extract():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('extract_title')} ==={Style.RESET_ALL}")
    libunity = select_file(i18n.get("select_libunity"), [("SO files", "*.so"), ("All files", "*.*")])
    if not libunity:
        print(f"{Fore.RED}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('libunity')}{libunity}")
    output = select_save_file(i18n.get("save_metadata"), [("DAT files", "*.dat"), ("All files", "*.*")], ".dat")
    if not output:
        print(f"{Fore.RED}{i18n.get('no_output_path')}{Style.RESET_ALL}")
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
        print(f"{Fore.GREEN}{i18n.get('extracted_to')}{output}{Style.RESET_ALL}")


def menu_decrypt():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('decrypt_title')} ==={Style.RESET_ALL}")
    input_file = select_file(i18n.get("select_encrypted"), [("DAT files", "*.dat"), ("All files", "*.*")])
    if not input_file:
        print(f"{Fore.RED}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('input')}{input_file}")
    output = select_save_file(i18n.get("save_decrypted"), [("DAT files", "*.dat"), ("All files", "*.*")], ".dat")
    if not output:
        print(f"{Fore.RED}{i18n.get('no_output_path')}{Style.RESET_ALL}")
        return
    try:
        with open(input_file, "rb") as f:
            metadata = f.read()
        decrypt_metadata(metadata, output)
    except Exception as e:
        print(f"{Fore.RED}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_info():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('info_title')} ==={Style.RESET_ALL}")
    input_file = select_file(i18n.get("select_metadata"), [("DAT files", "*.dat"), ("All files", "*.*")])
    if not input_file:
        print(f"{Fore.RED}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    print(f"{i18n.get('file')}{input_file}")
    try:
        with open(input_file, "rb") as f:
            data = f.read(512)
        print(f"\n{Fore.CYAN}=== {i18n.get('metadata_info_title')} ==={Style.RESET_ALL}")
        print(f"{i18n.get('magic')}{data[:4].hex().upper()}")
        version, desc = get_metadata_version(data)
        print(f"{i18n.get('version')}{version} ({desc})")
        print(f"{i18n.get('file_size')}{os.path.getsize(input_file)} bytes")
        if data[:4] != METADATA_MAGIC:
            print(f"{Fore.YELLOW}{i18n.get('warning_invalid_magic')}{Style.RESET_ALL}")
            decrypted, key = try_decrypt_metadata(data)
            if key:
                print(f"{Fore.GREEN}{i18n.get('possible_encryption')}{key}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_apk():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('apk_title')} ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{i18n.get('apk_select')}{Style.RESET_ALL}")
    input_path = select_file(i18n.get("select_apk"), [("APK files", "*.apk"), ("All files", "*.*")])
    if not input_path:
        print(f"{Fore.RED}{i18n.get('no_file_selected')}{Style.RESET_ALL}")
        return
    if os.path.isdir(input_path):
        print(f"{i18n.get('folder')}{input_path}")
    else:
        print(f"{i18n.get('apk')}{input_path}")
    output = select_save_file(i18n.get("save_metadata"), [("DAT files", "*.dat"), ("All files", "*.*")], ".dat")
    if not output:
        print(f"{Fore.RED}{i18n.get('no_output_path')}{Style.RESET_ALL}")
        return
    try:
        force = input(i18n.get("force_extract")).strip().lower() == 'y'
    except EOFError:
        force = False
    try:
        extract_from_apk(input_path, output, force)
    except Exception as e:
        print(f"{Fore.RED}{i18n.get('error')}{e}{Style.RESET_ALL}")


def menu_frida_memory_dump():
    clear_screen()
    print(f"\n{Fore.CYAN}=== {i18n.get('memory_dump_title')} ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{i18n.get('memory_dump_style')}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{i18n.get('memory_dump_usage')}{Style.RESET_ALL}")
    print(f"  python dump-metadata.py com.game.package")
    print(f"  python dump-metadata.py com.game.package -o 0x123456")
    print(f"\n{Fore.CYAN}{i18n.get('memory_dump_requires')}{Style.RESET_ALL}")
    output = select_save_file(i18n.get("save_frida"), [("JS files", "*.js"), ("All files", "*.*")], ".js")
    if not output:
        output = "dump-metadata.js"
    generate_frida_memory_dump_script(output)
    py_script = """import argparse
import frida
import sys
import os

def on_message(message, data):
    if message['type'] == 'log':
        print(message['payload'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('package_name')
    parser.add_argument('-o', '--offset', type=str, default=None)
    parser.add_argument('-s', '--size', type=int, default=None)
    parser.add_argument('-p', '--pattern', type=str, default="af 1b b1 fa 1? 00 00 00 00")
    args = parser.parse_args()

    device = frida.get_usb_device()
    session = device.attach(args.package_name)

    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dump-metadata.js')
    with open(script_path, 'r') as f:
        script_content = f.read()

    script = session.create_script(script_content)
    script.on('message', on_message)
    script.load()

    offset_val = int(args.offset, 16) if args.offset else 0
    script.exports.start(offset_val, args.size, args.pattern, args.package_name)
    sys.stdin.read()

if __name__ == '__main__':
    main()
"""
    try:
        py_output = input(i18n.get("generate_python")).strip().lower()
    except EOFError:
        return
    if py_output == 'y':
        try:
            py_path = input(i18n.get("output_path")).strip() or "dump-metadata.py"
        except EOFError:
            return
        with open(py_path, "w") as f:
            f.write(py_script)
        print(f"{Fore.GREEN}{i18n.get('python_saved')}{py_path}{Style.RESET_ALL}")


def interactive_menu():
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    loading_animation()
    while True:
        print_menu()
        try:
            choice = input(f"{Fore.CYAN}{i18n.get('select_option')}{Style.RESET_ALL}: ").strip()
        except EOFError:
            print(f"\n{Fore.GREEN}{i18n.get('exiting')}{Style.RESET_ALL}")
            break

        if choice == "1":
            menu_compare()
        elif choice == "2":
            menu_frida()
        elif choice == "3":
            menu_extract()
        elif choice == "4":
            menu_decrypt()
        elif choice == "5":
            menu_info()
        elif choice == "6":
            menu_apk()
        elif choice == "7":
            menu_frida_memory_dump()
        elif choice == "8":
            lang = i18n.toggle_language()
            print(f"{Fore.GREEN}{i18n.get('lang_changed')}{lang.upper()}{Style.RESET_ALL}")
        elif choice == "0":
            print(f"{Fore.GREEN}{i18n.get('exiting')}{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}{i18n.get('invalid_option')}{Style.RESET_ALL}")

        try:
            input(f"\n{Fore.CYAN}{i18n.get('press_enter')}{Style.RESET_ALL}")
        except EOFError:
            break


def main():
    parser = argparse.ArgumentParser(
        prog="Metadata-Worker",
        description="IL2CPP Metadata Tool - Compare, Extract, Decrypt, Dump APK",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    compare_parser = subparsers.add_parser("compare", help="Compare two metadata files")
    compare_parser.add_argument("file1", help="First metadata file")
    compare_parser.add_argument("file2", help="Second metadata file")
    compare_parser.add_argument(
        "-b", "--bytes", type=int, default=10, help="Bytes to compare"
    )

    frida_parser = subparsers.add_parser("frida", help="Generate Frida script")
    frida_parser.add_argument("offset", help="LoadMetaDataFile offset (e.g., 0x123456)")
    frida_parser.add_argument("-o", "--output", help="Output file path")

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

    info_parser = subparsers.add_parser("info", help="Show metadata info")
    info_parser.add_argument("input", help="Path to metadata file")

    apk_parser = subparsers.add_parser("apk", help="Extract metadata from APK or unpacked APK folder")
    apk_parser.add_argument("input", help="Path to APK file or unpacked APK folder")
    apk_parser.add_argument("-o", "--output", required=True, help="Output path")
    apk_parser.add_argument("-f", "--force", action="store_true", help="Force extract even if metadata looks encrypted")

    memory_dump_parser = subparsers.add_parser("memory-dump", help="Generate Frida memory dump script (CameroonD style)")
    memory_dump_parser.add_argument("-o", "--output", help="Output file path")

    menu_parser = subparsers.add_parser("menu", help="Interactive menu mode")

    args = parser.parse_args()

    if args.command and args.command != "menu":
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        loading_animation()

    if args.command == "compare":
        compare_metadata_files(args.file1, args.file2, args.bytes)
    elif args.command == "frida":
        generate_frida_script(args.offset, args.output)
    elif args.command == "extract":
        if not os.path.isfile(args.libunity):
            print(f"{Fore.RED}Error: {args.libunity} not found{Style.RESET_ALL}")
            sys.exit(1)
        result = extract_metadata(args.libunity, args.size)
        if result:
            metadata, _ = result
            with open(args.output, "wb") as f:
                f.write(metadata)
            print(f"{Fore.GREEN}Metadata extracted to {args.output}{Style.RESET_ALL}")
    elif args.command == "decrypt":
        if not os.path.isfile(args.input):
            print(f"{Fore.RED}Error: {args.input} not found{Style.RESET_ALL}")
            sys.exit(1)
        with open(args.input, "rb") as f:
            metadata = f.read()
        decrypt_metadata(metadata, args.output)
    elif args.command == "info":
        if not os.path.isfile(args.input):
            print(f"{Fore.RED}Error: {args.input} not found{Style.RESET_ALL}")
            sys.exit(1)
        with open(args.input, "rb") as f:
            data = f.read(512)
        print(f"\n{Fore.CYAN}=== Metadata Info ==={Style.RESET_ALL}")
        print(f"Magic: {data[:4].hex().upper()}")
        version, desc = get_metadata_version(data)
        print(f"Version: {version} ({desc})")
        print(f"File size: {os.path.getsize(args.input)} bytes")
        if data[:4] != METADATA_MAGIC:
            print(f"{Fore.YELLOW}Warning: Invalid magic bytes - file may be encrypted{Style.RESET_ALL}")
            decrypted, key = try_decrypt_metadata(data)
            if key:
                print(f"{Fore.GREEN}Possible encryption key: {key}{Style.RESET_ALL}")
    elif args.command == "apk":
        if not os.path.exists(args.input):
            print(f"{Fore.RED}Error: {args.input} not found{Style.RESET_ALL}")
            sys.exit(1)
        extract_from_apk(args.input, args.output, args.force)
    elif args.command == "memory-dump":
        output = args.output or "dump-metadata.js"
        generate_frida_memory_dump_script(output)
    elif args.command == "menu":
        interactive_menu()
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
