import argparse
import collections
import os
import struct
import sys

from colorama import Fore, Style, init
from elftools.elf.elffile import ELFFile
from tqdm import tqdm

init(autoreset=False)

parser = argparse.ArgumentParser()

parser.add_argument(
    "-s", action="store_true", help="Skip confirmation prompt", required=False
)

parser.add_argument(
    "--exclude-offset-candidates",
    metavar="exclude_offset_candidates",
    help="Exclude candidate offsets. In format `--exclude-offset-candidates 1,2,3`",
)
parser.add_argument("--libunity", metavar="libunity", help="libunity.so file")
parser.add_argument("--output", metavar="output", help="Reference metadata file")

args = parser.parse_args()

confirmed = args.s

exclude_offset_candidates = args.exclude_offset_candidates
libunity_path = args.libunity
output_path = args.output

print(f"{Fore.CYAN}NOTE: Current working directory: {os.getcwd()}")

if confirmed and (not libunity_path or not output_path):
    print(f"{Fore.RED + Style.BRIGHT}Error: -s requires --libunity and --output.{Style.RESET_ALL}")
    sys.exit(1)

while not confirmed or (not libunity_path and not output_path):
    if not libunity_path:
        libunity_path = input(
            f"{Fore.CYAN}Input libunity.so file path: {Style.RESET_ALL}"
        ).replace('"', "")
    if not output_path:
        output_path = input(
            f"{Fore.CYAN}Input decrypted metadata save path: {Style.RESET_ALL}"
        ).replace('"', "")

    if not os.path.isfile(libunity_path):
        print(f"{Fore.YELLOW}libunity.so file doesn't exist")
        libunity_path = ""
        continue

    with open(libunity_path, "rb") as f:
        is_elf = f.read(4) == b"\x7fELF"
    if not is_elf:
        bypass = input(
            f"{Fore.YELLOW}libunity.so file is not a valid ELF. Force continue? (y/N) {Style.RESET_ALL}"
        )
        if bypass.strip().lower() != "y":
            continue

    print(f"{Fore.CYAN}Using next files:")
    print(
        f"    {Fore.CYAN}libunity.so - {Fore.LIGHTMAGENTA_EX + Style.BRIGHT + libunity_path + Style.RESET_ALL}"
    )
    print(
        f"    {Fore.CYAN}Output - {Fore.LIGHTMAGENTA_EX + Style.BRIGHT + output_path + Style.RESET_ALL}"
    )

    if not confirmed:
        answer = input(f"{Fore.CYAN}Correct? {Style.RESET_ALL}").strip().lower()
        confirmed = answer[:1] in ("1", "y")
    if confirmed:
        print(f"{Fore.CYAN}Starting...")
        break

print(f"{Fore.CYAN}Starting search...")

with open(libunity_path, "rb") as libunity:
    elf = ELFFile(libunity)
    is64bit = elf.get_machine_arch() == "AArch64"

    load_segments = [
        (segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"], segment["p_offset"])
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_LOAD"
    ]

    def map_vaddr_to_offset(va):
        for start, end, offset in load_segments:
            if start <= va < end:
                return va - start + offset
        print(f"{Fore.RED}Error: Virtual address {va} not found in any LOAD segment.")
        sys.exit(-1)

    data_section = elf.get_section_by_name(".data")
    if data_section is None:
        print(f"{Fore.RED + Style.BRIGHT}Error: .data section not found.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.CYAN}Collecting and mapping relocation data...")

    relocations = []
    for section in elf.iter_sections():
        if section.header["sh_type"] not in ("SHT_REL", "SHT_RELA"):
            continue
        print(f"{Fore.CYAN}Processing relocation section: {section.name}")
        if is64bit:
            total = section.header["sh_size"] // (
                24
                if section.header["sh_type"] == "SHT_RELA"
                else 16
            )
        else:
            total = section.header["sh_size"] // (
                12
                if section.header["sh_type"] == "SHT_RELA"
                else 8
            )
        for relocation in tqdm(section.iter_relocations(), colour="green", unit="relocations", total=total):
            addr = relocation["r_offset"]

            if not data_section["sh_addr"] <= addr < data_section["sh_addr"] + data_section["sh_size"]:
                continue

            if is64bit:
                pointer = relocation["r_addend"]
            else:
                offset = map_vaddr_to_offset(addr)
                libunity.seek(offset)
                pointer = struct.unpack("<I", libunity.read(4))[0]

            if pointer != 0:
                relocations.append(pointer)

    print(f"{Fore.CYAN}Iterating over relocations to find metadata pointer...")

    pointer_candidates = []
    for addr in tqdm(relocations, colour="green", unit="relocations"):
        libunity.seek(addr - 16)
        candidate = libunity.read(16)
        if candidate == b"\x02\0\0\0\x7c\0\0\0\x06\x0b\0\0\0\x02\0\0\0":
            pointer_candidates.append(addr)

    if len(pointer_candidates) == 0:
        print(f"{Fore.RED + Style.BRIGHT}Error: No candidate found.{Style.RESET_ALL}")
        sys.exit(1)
    elif len(pointer_candidates) == 1:
        metadataptr = pointer_candidates[0]
        print(
            f"{Fore.GREEN + Style.BRIGHT}Successfully found metadata pointer in the binary at {hex(metadataptr)}.{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.YELLOW + Style.BRIGHT}Warning: More than one candidate found. Continuing with the first one.{Style.RESET_ALL}"
        )
        metadataptr = pointer_candidates[0]

    libunity.seek(metadataptr)
    metadata = libunity.read(30_000_000)

if is64bit:
    index = metadata.find(
        b"\x15\x00\x0c\x0c\x10\x1b\x23\0\0\0\0\0\x28\0\x2c\x10"
    )
else:
    index = metadata.find(
        b"\x00\x01\x01\x02\x01\x02\x02\x03"
    )

if index != -1:
    index += (4 - index % 4) % 4
    metadata = metadata[:index]
    print(f"{Fore.GREEN}Successfully found metadata end marker.")
    print(f"{Fore.CYAN}Metadata size: {len(metadata)} bytes.{Style.RESET_ALL}")
else:
    print(
        f"{Fore.RED + Style.BRIGHT}Error: Failed find the metadata end marker in the metadata.{Style.RESET_ALL}"
    )
    sys.exit(1)

with open("debug-metadata.bin", "wb") as f:
    print(
        f"{Fore.CYAN}Dumping the debug metadata to 'debug-metadata.bin' for debugging purposes."
    )
    f.write(metadata)

print(f"{Fore.GREEN}Starting decryption of the metadata...")

fields = []
for i in range(0, 256, 4):
    value = struct.unpack("<I", metadata[i : i + 4])[0]
    if value > 0 and value < len(metadata):
        fields.append(value)

offset_candidates = []

for field in fields:
    if field < 8192 or field % 4 != 0:
        if field == 256:
            offset_candidates.append(field)
        continue
    if field > len(metadata) / 3:
        offset_candidates.append(field)
        continue
    behind_data = metadata[field - 4096 : field]
    ahead_data = metadata[field : field + 4096]

    zeroes_behind = behind_data.count(b"\0")
    zeroes_ahead = ahead_data.count(b"\0")

    counter_behind = collections.Counter(behind_data)
    counter_ahead = collections.Counter(ahead_data)

    keys = set(counter_behind.keys()) | set(counter_ahead.keys())

    freq_behind = {k: counter_behind.get(k, 0) / 4096 for k in keys}
    freq_ahead = {k: counter_ahead.get(k, 0) / 4096 for k in keys}

    dist = sum(abs(freq_behind[k] - freq_ahead[k]) for k in keys)

    score = abs(zeroes_behind - zeroes_ahead) / 512 + dist
    if score > 0.75:
        offset_candidates.append(field)

offset_candidates = list(set(offset_candidates))
offset_candidates.sort()

if exclude_offset_candidates:
    for excluded in exclude_offset_candidates.split(","):
        todelete = int(excluded)
        print(f"{Fore.LIGHTCYAN_EX}Excluding offset {todelete}.")
        try:
            offset_candidates.remove(todelete)
        except ValueError:
            print(
                f"{Fore.YELLOW + Style.BRIGHT}Error: Offset {todelete} not found in candidates list.{Style.RESET_ALL}"
            )

print(f"{Fore.CYAN}Found {len(offset_candidates)} potential offsets.")

offsets_to_sizes: list[tuple[int, int]] = []
only_sizes = list(filter(lambda x: x not in offset_candidates, fields))
for possible_offset in offset_candidates:
    found = False

    size_search_pool = only_sizes if possible_offset != 256 else fields
    for size in size_search_pool:
        if size != possible_offset and size != 0 and size < len(metadata) / 3:
            if size + possible_offset == len(metadata):
                print(
                    f"{Fore.CYAN}Hit the last offset {possible_offset} with {size = }, adding it to "
                    f"the list of potential offsets."
                )
                offsets_to_sizes.append((possible_offset, size))
                found = True
                break

            for next_offset in offset_candidates:
                if (
                    possible_offset + size == next_offset
                    and possible_offset != next_offset
                ):
                    offsets_to_sizes.append((possible_offset, size))
                    print(
                        f"{Fore.CYAN}Offset {possible_offset} + {size} (={possible_offset + size}) is close to offset "
                        f"{next_offset}, adding it to the list of potential offsets."
                    )
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
        is_size_big_enough = (next_offset is not None) and (
            next_offset - possible_offset > 4096
        )
        did_the_last_pair_add_up_to_this = (
            sum(offsets_to_sizes[-1]) == possible_offset
            if offsets_to_sizes and not is_256
            else True
        )
        if (
            is_256 or is_big_enough or is_size_big_enough
        ) and did_the_last_pair_add_up_to_this:
            size = (
                (next_offset - possible_offset)
                if next_offset is not None
                else len(metadata) - possible_offset
            )
            print(
                f"{Fore.YELLOW}Offset {possible_offset} does not have a matching size, but it's most likely one with {size = }"
            )
            offsets_to_sizes.append((possible_offset, size))
        else:
            only_sizes.append(possible_offset)
            print(
                f"{Fore.YELLOW}Offset {possible_offset} does not have a matching size, and it's probably a size."
            )

offsets_to_sizes = sorted(offsets_to_sizes, key=lambda item: item[0])

if len(offsets_to_sizes) == 29:
    print(
        f"{Fore.GREEN + Style.BRIGHT}Found 29 unique valid offsets in the metadata at: {offsets_to_sizes}.{Style.RESET_ALL}"
    )
else:
    print(
        f"{Fore.YELLOW + Style.BRIGHT}Found {len(offsets_to_sizes)} offsets in the metadata at: {offsets_to_sizes}.{Style.RESET_ALL}"
    )

print(f"{Fore.CYAN}Starting reconstruction using heuristic search...")

reconstructed_metadata = bytearray(
    b"\xaf\x1b\xb1\xfa\x1f\0\0\0\0\x01\00\00" + b"\0" * 244
)
reconstructed_offsets = []


def apply_heuristic(
    name, callback, struct_sig, prefer_the_lowest_size, add_if_contains
):
    found = []
    for offset, size in offsets_to_sizes:
        data = metadata[offset : offset + size]

        if add_if_contains and add_if_contains in data:
            found.append((offset, size, data))
            break

        if not struct_sig:
            continue

        entries = []

        step = struct.calcsize(struct_sig)
        for i in range(0, len(data), step):
            try:
                fields = struct.unpack_from(struct_sig, data, i)
                if len(struct_sig) == 2:
                    entries.append(fields[0])
                else:
                    entries.append(fields)
            except struct.error:
                break

        if callback and callback(entries):
            found.append((offset, size, data))
    if not found:
        print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for {name}")
        sys.exit(1)

    found.sort(key=lambda x: x[1], reverse=not prefer_the_lowest_size)
    offsets_to_sizes.remove(found[0][:2])

    print(
        f"{Fore.CYAN}Found {name} at offset {found[0][0]}: Adding to reconstructed fields."
    )

    reconstructed_offsets.append(found[0][0])


def stringLiteral_callback(entries):
    expected_index = entries[0][1]
    for entry_size, entry_index in entries:
        if entry_index != expected_index:
            return False
        expected_index += entry_size
    return True


def events_callback(entries):
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


def properties_callback(entries):
    for _, _, _, _, token in entries:
        if token & 0xFF000000 != 0x17000000:
            return False
    return True


def methods_callback(entries):
    for _, _, _, _, _, _, token, _, _, _, _ in entries:
        if token & 0xFF000000 != 0x06000000:
            return False
    return True


def parameterDefaultValues_callback(entries):
    last_parameter_index = entries[0][0]
    for parameter_index, _, _ in entries:
        if last_parameter_index > parameter_index:
            return False
        last_parameter_index = parameter_index
    return True


def fieldDefaultValues_callback(entries):
    last_field_index = entries[0][0]
    for field_index, _, _ in entries:
        if last_field_index > field_index:
            return False
        last_field_index = field_index
    return True


def fieldMarshaledSizes_callback(entries):
    last_field_index = entries[0][0]
    for field_index, _, _ in entries:
        if last_field_index > field_index:
            return False
        last_field_index = field_index
    return True


def parameters_callback(entries):
    for _, token, _ in entries:
        if token & 0xFF000000 != 0x08000000:
            return False
    return True


def fields_callback(entries):
    for _, _, token in entries:
        if token & 0xFF000000 != 0x04000000:
            return False
    return True


def genericParameters_callback(entries):
    expected_constraints_start = entries[0][2]
    for _, name_index, constraints_start, constraints_count, _, _ in entries:
        if constraints_start not in (0, expected_constraints_start) or name_index < 256:
            return False
        expected_constraints_start += constraints_count
    return True


def genericParameterConstraints_callback(entries):
    for constraint in entries:
        if 1024576 < constraint or constraint < 256:
            return False
    return True


def genericContainers_callback(entries):
    for _, type_argc, is_method, _ in entries:
        if not (is_method == 0 or is_method == 1) or type_argc > 128:
            return False
    return True


def nestedTypes_callback(entries):
    right_count, last_type_definition_index, attempts = 0, 0, 0

    for type_definition_index in entries:
        attempts += 1
        if type_definition_index > last_type_definition_index:
            right_count += 1
        else:
            right_count -= 1
        if right_count > 256:
            return True
        if right_count < -4 or type_definition_index > 0x01000000 or attempts > 512:
            return False
        last_type_definition_index = type_definition_index
    return True


def interfaces_callback(entries):
    for constraint in entries:
        if 1024576 < constraint or constraint < 256:
            return False
    return True


def vtableMethods_callback(entries):
    for encoded_method_index in entries:
        if encoded_method_index != 1 and encoded_method_index & 0xE0000000 == 0:
            return False
    return True


def interfacesOffsets_callback(entries):
    for interface_type_index, interface_offset in entries:
        if (
            interface_offset > 256
            or 256 > interface_type_index
            or interface_type_index > 65535
        ):
            return False
    return True


def typeDefinitions_callback(entries):
    for entry in entries:
        if entry[25] & 0xFF000000 != 0x02000000:
            return False
    return True


def images_callback(entries):
    entries = entries[: len(entries) - 2]
    for entry in entries:
        if entry[7] != 1:
            return False
    return True


def assemblies_callback(entries):
    for entry in entries:
        token = entry[1]
        if token & 0xFF000000 != 0x20000000:
            return False
    return True


def fieldRefs_callback(entries):
    for type_index, field_index in entries:
        if type_index < 256 or field_index > 2048:
            return False
    return True


def referencedAssemblies_callback(entries):
    if not entries:
        return True
    mean_averege = sum(entries) / len(entries)
    for assembly in entries:
        if assembly > 256 or not 30 < mean_averege < 40:
            return False
    return True


def attributeDataRange_callback(entries):
    right = 0
    last_index = entries[0][1]
    if last_index != 0:
        return False
    for token, index in entries:
        if token & 0xFF000000 == 0:
            right -= 10
        else:
            right += 2
        if index < last_index:
            right -= 2
        else:
            right += 1
        if right > 2048:
            return True
        elif right < -16:
            return False
    return True


def unresolvedIndirectCallParameterTypes_callback(entries):
    for parameter in entries:
        if parameter < 256 or parameter > 70000:
            return False
    return True


def unresolvedIndirectCallParameterTypeRanges_callback(entries):
    expected_start = entries[0][0]
    for start, length in entries:
        if start != expected_start:
            return False
        expected_start += length
    return True


def exportedTypeDefinitions_callback(entries):
    for entry in entries:
        if entry < 64 or entry > 131072:
            return False
    return True


apply_heuristic("stringLiteral", stringLiteral_callback, "<II", True, None)
apply_heuristic(
    "stringLiteralData", None, None, True, b"\x00\x00\x00\x00\x01\x09\x00\x00\x01"
)
apply_heuristic("string", None, None, True, b"Assembly-CSharp\0\0\0\0\0Assembl")
apply_heuristic("events", events_callback, "<IIIIII", False, None)
apply_heuristic("properties", properties_callback, "<IIIII", False, None)
apply_heuristic("methods", methods_callback, "<IIIIIIIHHHH", False, None)
apply_heuristic(
    "parameterDefaultValues", parameterDefaultValues_callback, "<III", True, None
)
apply_heuristic("fieldDefaultValues", fieldDefaultValues_callback, "<III", False, None)
apply_heuristic(
    "fieldAndParameterDefaultValuesData",
    None,
    None,
    False,
    b"\\Assets\\ThirdParty\\I2\\Localization\\Scripts\\Utils\\SetLanguage.cs",
)
apply_heuristic("fieldMarshaledSizes", fieldMarshaledSizes_callback, "<III", True, None)
apply_heuristic("parameters", parameters_callback, "<III", True, None)
apply_heuristic("fields", fields_callback, "<III", True, None)
apply_heuristic("genericParameters", genericParameters_callback, "<IIHHHH", True, None)
apply_heuristic(
    "genericParameterConstraints", genericParameterConstraints_callback, "<I", True, None
)
apply_heuristic("genericContainers", genericContainers_callback, "<IIII", False, None)
apply_heuristic("nestedTypes", nestedTypes_callback, "<I", False, None)
apply_heuristic("interfaces", interfaces_callback, "<I", False, None)
apply_heuristic("vtableMethods", vtableMethods_callback, "<I", False, None)
apply_heuristic("interfaceOffsets", interfacesOffsets_callback, "<II", False, None)
apply_heuristic(
    "typeDefinitions",
    typeDefinitions_callback,
    "<IIIIIIIIIIIIIIIIHHHHHHHHII",
    False,
    None,
)
apply_heuristic("images", images_callback, "<IIIIIIIIII", False, None)
apply_heuristic("assemblies", assemblies_callback, "<IIIIIIIIIIIIIIII", False, None)
apply_heuristic("fieldRefs", fieldRefs_callback, "<II", False, None)
apply_heuristic(
    "referencedAssemblies", referencedAssemblies_callback, "<I", False, None
)
apply_heuristic("attributeData", None, None, False, b"NewFragmentBox")
apply_heuristic("attributeDataRange", attributeDataRange_callback, "<II", False, None)
apply_heuristic(
    "unresolvedIndirectCallParameterTypes",
    unresolvedIndirectCallParameterTypes_callback,
    "<I",
    False,
    None,
)
apply_heuristic(
    "unresolvedIndirectCallParameterTypeRanges",
    unresolvedIndirectCallParameterTypeRanges_callback,
    "<II",
    False,
    None,
)
apply_heuristic(
    "exportedTypeDefinitions", exportedTypeDefinitions_callback, "<I", False, None
)

print(f"{Fore.GREEN + Style.BRIGHT}Constructing the metadata...{Style.RESET_ALL}")

position_in_header = 0


def add_size_to_header(size):
    global position_in_header
    size_bytes = struct.pack("<I", size)
    reconstructed_metadata[12 + position_in_header : 16 + position_in_header] = (
        size_bytes
    )
    new_size = (
        struct.unpack(
            "<I",
            reconstructed_metadata[8 + position_in_header : 12 + position_in_header],
        )[0]
        + size
    )
    reconstructed_metadata[16 + position_in_header : 20 + position_in_header] = (
        struct.pack("<I", new_size)
    )
    position_in_header += 8


offset_lookup = sorted(reconstructed_offsets)
for i in range(31):
    if i < 28:
        offset = reconstructed_offsets[i]
        lookup_index = offset_lookup.index(offset)
        if lookup_index < 28:
            size = offset_lookup[lookup_index + 1] - offset
            print(f"{Fore.CYAN}Added offset {offset} with size {size} to the header.")
        else:
            size = len(metadata) - offset
        add_size_to_header(size)
        reconstructed_metadata += metadata[offset : offset + size]
    elif i == 28 or i == 29:
        add_size_to_header(0)
        print(f"{Fore.CYAN}Added a zero field for the {i}th entry.")
    elif i == 30:
        reconstructed_metadata[252:256] = struct.pack(
            "<I",
            len(metadata) - struct.unpack("<I", reconstructed_metadata[248:252])[0],
        )
        offset = reconstructed_offsets[28]
        size = len(metadata) - offset
        reconstructed_metadata += metadata[offset : offset + size]
        print(f"{Fore.CYAN}Fixed the last size in the header.")

if os.path.isdir(output_path):
    output_path = os.path.join(output_path, "output-metadata.dat")
with open(output_path, "wb") as f:
    f.write(reconstructed_metadata)

print(f"{Fore.MAGENTA + Style.BRIGHT}Output written to {output_path}")
print(
    f"{Fore.GREEN}Successfully extracted and decrypted the metadata! I would be happy, if you starred my github "
    f"{Fore.BLUE}\033]8;;https://github.com/Michel-M-code/Metadata-Decryptor\33\\repository\033]8;;\033\\{Fore.LIGHTGREEN_EX + Style.BRIGHT}! (ctrl + click)\n"
    f"{Fore.CYAN}If anything goes wrong during the dump, feel free to open an issue on the said repository, this would help me to fix it quicker.{Style.RESET_ALL}"
)
