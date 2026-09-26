import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main as mw


def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    keys = struct.unpack_from("<4I", key, 0)
    words = len(data) // 4
    values = list(struct.unpack_from(f"<{words}I", data, 0))
    rounds = 6 + 52 // words
    total = 0
    delta = mw.XXTEA_DELTA
    z = values[words - 1]
    for _ in range(rounds):
        total = (total + delta) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(words - 1):
            y = values[p + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
                (total ^ y) + (keys[(p & 3) ^ e] ^ z)
            )
            values[p] = (values[p] + mx) & 0xFFFFFFFF
            z = values[p]
        y = values[0]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
            (total ^ y) + (keys[((words - 1) & 3) ^ e] ^ z)
        )
        values[words - 1] = (values[words - 1] + mx) & 0xFFFFFFFF
        z = values[words - 1]
    return struct.pack(f"<{words}I", *values)


class TestXor(unittest.TestCase):
    def test_repeating_key(self):
        data = bytes(range(32))
        key = [0x53, 0xA3, 0x12]
        encrypted = mw.decrypt_xor(data, key)
        self.assertEqual(mw.decrypt_xor(encrypted, key), data)

    def test_leading_zero_bytes_survive(self):
        data = b"\x00\x00\x00\x01\x02"
        encrypted = mw.decrypt_xor(data, [0xFF, 0xFF, 0xFF, 0xFF])
        self.assertEqual(len(encrypted), len(data))
        self.assertEqual(mw.decrypt_xor(encrypted, [0xFF] * 4), data)

    def test_empty_key_is_identity(self):
        data = b"payload"
        self.assertEqual(mw.decrypt_xor(data, []), data)

    def test_striped_xor_touches_every_other_block(self):
        data = bytes([0x40] * (mw.STRIPED_XOR_STRIPE * 2 + 8))
        out = mw.decrypt_striped_xor(data, 0xA3)
        self.assertEqual(out[:8], bytes([0x40 ^ 0xA3] * 8))
        self.assertEqual(
            out[mw.STRIPED_XOR_STRIPE : mw.STRIPED_XOR_STRIPE + 8], bytes([0x40] * 8)
        )
        self.assertEqual(
            out[mw.STRIPED_XOR_STRIPE * 2 : mw.STRIPED_XOR_STRIPE * 2 + 8],
            bytes([0x40 ^ 0xA3] * 8),
        )

    def test_known_header_key_detection(self):
        plain = mw.METADATA_MAGIC + struct.pack("<I", 29) + b"\x00" * 64
        self.assertIsNone(mw.auto_header_xor_key(plain))
        data = bytes(byte ^ 0x55 for byte in plain[:8])
        self.assertEqual(mw.auto_header_xor_key(data), [0x55] * 4)

    def test_header_key_rejects_four_distinct_bytes(self):
        junk = (
            bytes(
                [
                    mw.METADATA_MAGIC[0] ^ 0x11,
                    mw.METADATA_MAGIC[1] ^ 0x22,
                    mw.METADATA_MAGIC[2] ^ 0x33,
                    mw.METADATA_MAGIC[3] ^ 0x44,
                ]
            )
            + b"\x00" * 8
        )
        self.assertIsNone(mw.auto_header_xor_key(junk))

    def test_periodic_key_is_not_deduplicated(self):
        target = b"\x00" * 8 + b"\x01\x00\x00\x00"
        key = bytes([0x41, 0x42, 0x43])
        blob = bytearray(b"\x00" * 0x200)
        blob[0x100 : 0x100 + len(target)] = bytes(
            target[i] ^ key[i % 3] for i in range(len(target))
        )
        found = mw.auto_find_xor_key(bytes(blob))
        self.assertIsNotNone(found)
        self.assertEqual(bytes(found or []), key)
        self.assertEqual(len(found or []), 3)


class TestRc4(unittest.TestCase):
    def test_known_vector(self):
        self.assertEqual(
            mw.decrypt_rc4(b"Plaintext", b"Key"),
            bytes.fromhex("BBF316E8D940AF0AD3"),
        )

    def test_wiki_key_vector(self):
        self.assertEqual(
            mw.decrypt_rc4(b"Attack at dawn", b"Secret"),
            bytes.fromhex("45A01F645FC35B383552544B9BF5"),
        )

    def test_empty_key(self):
        self.assertEqual(mw.decrypt_rc4(b"abc", b""), b"abc")


class TestXxtea(unittest.TestCase):
    def test_round_trip(self):
        data = struct.pack("<16I", *range(100, 116))
        key = bytes(range(16))
        encrypted = xxtea_encrypt(data, key)
        self.assertNotEqual(encrypted, data)
        self.assertEqual(mw.decrypt_xxtea(encrypted, key, len(data) // 4), data)

    def test_short_and_invalid_inputs(self):
        self.assertEqual(mw.decrypt_xxtea(b"1234", b"k" * 16), b"1234")
        self.assertEqual(mw.decrypt_xxtea(b"12345678", b"short"), b"12345678")

    def test_tail_is_preserved(self):
        data = struct.pack("<4I", 1, 2, 3, 4) + b"trailing"
        key = bytes(range(16))
        out = mw.decrypt_xxtea(data, key, 4)
        self.assertTrue(out.endswith(b"trailing"))


class TestMetadataHeader(unittest.TestCase):
    def test_is_valid_metadata(self):
        self.assertTrue(mw.is_valid_metadata(mw.METADATA_MAGIC + b"\x00"))
        self.assertFalse(mw.is_valid_metadata(b"\xf1\xfa"))
        self.assertFalse(mw.is_valid_metadata(b"\x00\x00\x00\x00"))

    def test_version_lookup(self):
        version, desc = mw.get_metadata_version(
            mw.METADATA_MAGIC + struct.pack("<I", 29)
        )
        self.assertEqual(version, 29)
        self.assertEqual(desc, "Unity 2019.1")
        self.assertEqual(mw.get_metadata_version(b"\xf1\xfa\x11")[0], -1)

    def test_reconstruction_is_consistent(self):
        sizes = [0x400, 0x200, 0x800, 0x100, 0x40]
        offsets = []
        cursor = 0x100
        for size in sizes:
            offsets.append(cursor)
            cursor += size
        metadata = (bytes(range(256)) * (cursor // 256 + 1))[:cursor]
        out = mw.build_reconstructed_metadata(metadata, offsets)
        self.assertEqual(out[:4], mw.METADATA_HEADER_MAGIC)
        self.assertEqual(struct.unpack_from("<I", out, 4)[0], 31)
        self.assertEqual(struct.unpack_from("<I", out, 8)[0], 0x100)
        self.assertEqual(len(out), 0x100 + cursor - 0x100)
        running = 0x100
        for index, size in enumerate(sizes):
            base = 8 + index * 8
            self.assertEqual(struct.unpack_from("<I", out, base)[0], running)
            self.assertEqual(struct.unpack_from("<I", out, base + 4)[0], size)
            running += size
        self.assertEqual(struct.unpack_from("<I", out, 8 + len(sizes) * 8 + 4)[0], 0)
        self.assertEqual(
            struct.unpack_from("<I", out, 8 + (len(sizes) + 1) * 8 + 4)[0], 0
        )
        self.assertEqual(struct.unpack_from("<I", out, 252)[0], 0)
        self.assertEqual(len(out), 256 + sum(sizes))
        for slot in range(mw.HEADER_SLOTS):
            offset = struct.unpack_from("<I", out, 8 + slot * 8)[0]
            size = struct.unpack_from("<I", out, 12 + slot * 8)[0]
            if slot + 1 < mw.HEADER_SLOTS:
                nxt = struct.unpack_from("<I", out, 16 + slot * 8)[0]
                self.assertEqual(nxt, offset + size)

    def test_reconstruction_writes_tail_for_full_slot_table(self):
        sizes = [0x100] * 29
        offsets = []
        cursor = 0x100
        for size in sizes:
            offsets.append(cursor)
            cursor += size
        metadata = bytes((index & 0xFF) for index in range(cursor))
        out = mw.build_reconstructed_metadata(metadata, offsets)
        self.assertEqual(len(out), len(metadata))
        self.assertEqual(struct.unpack_from("<I", out, 8)[0], 0x100)
        for index in range(28):
            base = 8 + index * 8
            self.assertEqual(struct.unpack_from("<I", out, base + 4)[0], 0x100)
            self.assertEqual(
                struct.unpack_from("<I", out, base)[0], 0x100 * (index + 1)
            )
        self.assertEqual(struct.unpack_from("<I", out, 8 + 28 * 8 + 4)[0], 0)
        self.assertEqual(struct.unpack_from("<I", out, 8 + 29 * 8 + 4)[0], 0)
        self.assertEqual(struct.unpack_from("<I", out, 8 + 30 * 8)[0], 0x100 * 29)
        self.assertEqual(struct.unpack_from("<I", out, 252)[0], 0x100)
        total = 256
        for slot in range(mw.HEADER_SLOTS):
            total += struct.unpack_from("<I", out, 12 + slot * 8)[0]
        self.assertEqual(total, len(out))

    def test_reconstruction_keeps_body_order(self):
        metadata = bytes([0x41] * 0x400) + bytes([0x42] * 0x200)
        out = mw.build_reconstructed_metadata(metadata, [0, 0x400])
        self.assertEqual(out[256 : 256 + 0x400], bytes([0x41] * 0x400))
        self.assertEqual(out[256 + 0x400 : 256 + 0x600], bytes([0x42] * 0x200))

    def test_reconstruction_with_missing_sections(self):
        metadata = bytes([0x7E] * 0x800)
        out = mw.build_reconstructed_metadata(metadata, [0x100, 0x400])
        self.assertEqual(len(out), 256 + 0x700)
        self.assertEqual(struct.unpack_from("<I", out, 8)[0], 0x100)
        self.assertEqual(struct.unpack_from("<I", out, 12)[0], 0x300)
        self.assertEqual(struct.unpack_from("<I", out, 16)[0], 0x400)
        self.assertEqual(struct.unpack_from("<I", out, 20)[0], 0x400)


class TestCandidates(unittest.TestCase):
    def test_offset_candidates_sorted_and_unique(self):
        metadata = bytearray(b"\x00" * 0x8000)
        metadata[0x2000:] = b"\xab" * (0x8000 - 0x2000)
        struct.pack_into("<I", metadata, 0, 256)
        struct.pack_into("<I", metadata, 8, 0x2000)
        struct.pack_into("<I", metadata, 12, 0x2000)
        found = mw.find_offset_candidates(bytes(metadata))
        self.assertEqual(found, sorted(set(found)))
        self.assertIn(256, found)
        self.assertIn(0x2000, found)

    def test_offset_candidates_on_tiny_input(self):
        self.assertEqual(mw.find_offset_candidates(b"\x00" * 8), [])

    def test_offsets_to_sizes_are_sorted(self):
        metadata = bytearray(0x8000)
        struct.pack_into("<I", metadata, 0, 256)
        struct.pack_into("<I", metadata, 8, 0x2000)
        struct.pack_into("<I", metadata, 12, 0x1000)
        struct.pack_into("<I", metadata, 16, 0x2000)
        pairs = mw.build_offsets_to_sizes(bytes(metadata), [256, 0x1000, 0x2000])
        self.assertEqual(pairs, sorted(pairs))
        self.assertEqual(sum(size for _, size in pairs[:1]), 0x1000 - 256)


class TestElf(unittest.TestCase):
    def test_vaddr_mapping(self):
        segments = [(0x1000, 0x2000, 0x400), (0x40000, 0x50000, 0x8000)]
        self.assertEqual(mw.map_vaddr_to_offset(0x1000, segments), 0x400)
        self.assertEqual(mw.map_vaddr_to_offset(0x1FFF, segments), 0x13FF)
        self.assertEqual(mw.map_vaddr_to_offset(0x41000, segments), 0x9000)
        self.assertIsNone(mw.map_vaddr_to_offset(0x3000, segments))
        self.assertIsNone(mw.map_vaddr_to_offset(0x50000, segments))

    def test_end_marker_truncation_drops_the_sentinel(self):
        body = b"\x11" * 32 + mw.METADATA_MARKER_64 + b"\x22" * 16
        trimmed, is64 = mw.truncate_at_end_marker(body)
        self.assertTrue(is64)
        self.assertEqual(trimmed, b"\x11" * 32)
        self.assertNotIn(mw.METADATA_MARKER_64, trimmed)

    def test_end_marker_truncation_aligns_up(self):
        body = b"\x11" * 33 + mw.METADATA_MARKER_64 + b"\x22" * 16
        trimmed, _ = mw.truncate_at_end_marker(body)
        self.assertEqual(len(trimmed) % 4, 0)
        self.assertEqual(len(trimmed), 36)

    def test_end_marker_32bit(self):
        body = b"\x11" * 16 + mw.METADATA_MARKER_32 + b"\x22" * 16
        trimmed, is64 = mw.truncate_at_end_marker(body)
        self.assertFalse(is64)
        self.assertEqual(trimmed, b"\x11" * 16)

    def test_end_marker_missing_keeps_data(self):
        body = b"\x11" * 64
        trimmed, is64 = mw.truncate_at_end_marker(body)
        self.assertEqual(trimmed, body)
        self.assertFalse(is64)

    def test_embedded_metadata_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "libunity.so")
            blob = b"\x7fELF" + b"\x00" * 0x40
            blob += mw.METADATA_MAGIC + struct.pack("<I", 29) + b"\x00" * 0x100
            with open(path, "wb") as handle:
                handle.write(blob)
            self.assertTrue(mw.is_elf_file(path))
            self.assertEqual(mw.find_embedded_metadata(path), 0x44)
            self.assertEqual(mw.find_pattern(path, mw.METADATA_MAGIC), [0x44])

    def test_embedded_metadata_ignores_bad_version(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "blob.bin")
            blob = mw.METADATA_MAGIC + struct.pack("<I", 0xDEADBEEF)
            blob += mw.METADATA_MAGIC + struct.pack("<I", 31) + b"\x00" * 32
            with open(path, "wb") as handle:
                handle.write(blob)
            self.assertEqual(mw.find_embedded_metadata(path), 8)

    def test_embedded_metadata_falls_back_to_first_hit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "blob.bin")
            blob = mw.METADATA_MAGIC + struct.pack("<I", 0xDEADBEEF) + b"\x00" * 32
            with open(path, "wb") as handle:
                handle.write(blob)
            self.assertEqual(mw.find_embedded_metadata(path), 0)

    def test_empty_file_is_handled(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "empty.bin")
            open(path, "wb").close()
            self.assertEqual(mw.find_pattern(path, b"\x00\x01"), [])
            self.assertIsNone(mw.find_embedded_metadata(path))
            self.assertFalse(mw.is_elf_file(path))


class TestDecryptPipeline(unittest.TestCase):
    def test_plain_metadata_passes_through(self):
        data = mw.METADATA_MAGIC + struct.pack("<I", 29) + os.urandom(512)
        out, key = mw.try_decrypt_metadata(data)
        self.assertIsNone(key)
        self.assertEqual(out, data)

    def test_single_byte_xor_is_detected(self):
        plain = mw.METADATA_MAGIC + struct.pack("<I", 29) + os.urandom(2048)
        out, key = mw.try_decrypt_metadata(mw.decrypt_xor(plain, [0xA3] * 4))
        self.assertIsNotNone(key)
        self.assertEqual(out, plain)

    def test_unknown_encryption_is_reported_as_absent(self):
        out, key = mw.try_decrypt_metadata(os.urandom(4096))
        self.assertIsNone(key)
        self.assertEqual(len(out), 4096)

    def test_end_to_end_decrypt_writes_output(self):
        sections = 29
        base = 0x100
        size = 0x800
        metadata = bytearray(base + sections * size)
        struct.pack_into("<4sI", metadata, 0, mw.METADATA_MAGIC, 29)
        for index in range(sections):
            struct.pack_into("<II", metadata, 8 + index * 8, base + index * size, size)
        payload = bytes(metadata)
        with tempfile.TemporaryDirectory() as folder:
            source = os.path.join(folder, "in.dat")
            target = os.path.join(folder, "nested", "out.dat")
            with open(source, "wb") as handle:
                handle.write(payload)
            with open(source, "rb") as handle:
                loaded = handle.read()
            mw.dump_debug = False
            try:
                ok = mw.decrypt_metadata(loaded, target)
            finally:
                mw.dump_debug = True
            self.assertTrue(ok is not None)
            self.assertTrue(os.path.isfile(target))
            with open(target, "rb") as handle:
                out = handle.read()
        self.assertLessEqual(len(out), len(payload))
        self.assertEqual(out[:4], mw.METADATA_HEADER_MAGIC)
        self.assertEqual(struct.unpack_from("<I", out, 8)[0], base)
        total = 256
        for slot in range(mw.HEADER_SLOTS):
            total += struct.unpack_from("<I", out, 12 + slot * 8)[0]
        self.assertEqual(total, len(out))

    def test_too_small_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = os.path.join(folder, "out.dat")
            mw.dump_debug = False
            try:
                ok = mw.decrypt_metadata(b"\x01\x02\x03", target)
            finally:
                mw.dump_debug = True
        self.assertFalse(ok)


class TestHeuristics(unittest.TestCase):
    def test_all_sections_present(self):
        names = [spec[0] for spec in mw.get_heuristics()]
        self.assertEqual(len(names), 29)
        self.assertEqual(len(set(names)), 29)

    def test_parse_entries_scalar_and_tuple(self):
        data = struct.pack("<3I", 5, 6, 7) + struct.pack("<2I", 8, 9)
        self.assertEqual(mw.parse_entries(data, "<I"), [5, 6, 7, 8, 9])
        self.assertEqual(mw.parse_entries(data, "<II"), [(5, 6), (7, 8)])

    def test_parse_entries_ignores_trailing_bytes(self):
        data = struct.pack("<2I", 1, 2) + b"\x03"
        self.assertEqual(mw.parse_entries(data, "<II"), [(1, 2)])

    def test_token_callback(self):
        callback = mw.token_cb_at(1, 0x06000000)
        self.assertTrue(callback([(0, 0x06000001), (0, 0x0600FFFF)]))
        self.assertFalse(callback([(0, 0x06000001), (0, 0x04000001)]))

    def test_apply_heuristic_marker_selection(self):
        metadata = (
            b"\x00" * 0x100
            + b"Assembly-CSharp\x00\x00\x00\x00\x00Assembl"
            + b"\x00" * 0x100
        )
        spec = (
            "string",
            None,
            None,
            True,
            b"Assembly-CSharp\x00\x00\x00\x00\x00Assembl",
        )
        result, remaining = mw.apply_heuristic(spec, metadata, [(0, 0x200)])
        self.assertIsNotNone(result)
        self.assertEqual(result[0] if result else -1, 0)
        self.assertEqual(remaining, [])

    def test_apply_heuristic_without_candidates(self):
        spec = ("interfaces", mw.interfaces_cb, "<I", False, None)
        result, remaining = mw.apply_heuristic(spec, b"\x00" * 0x100, [])
        self.assertIsNone(result)
        self.assertEqual(remaining, [])

    def test_empty_entries_do_not_match(self):
        spec = ("interfaces", mw.interfaces_cb, "<I", False, None)
        result, _ = mw.apply_heuristic(spec, b"\x01\x02\x03", [(0, 2)])
        self.assertIsNone(result)


class TestI18n(unittest.TestCase):
    def test_keys_match_between_languages(self):
        english = set(mw.i18n.LANGUAGES["en"])
        russian = set(mw.i18n.LANGUAGES["ru"])
        self.assertEqual(english - russian, set())
        self.assertEqual(russian - english, set())

    def test_placeholders_match(self):
        for key, value in mw.i18n.LANGUAGES["en"].items():
            english = sorted(part.split("}")[0] for part in value.split("{")[1:])
            russian = sorted(
                part.split("}")[0]
                for part in mw.i18n.LANGUAGES["ru"][key].split("{")[1:]
            )
            self.assertEqual(english, russian, key)

    def test_language_switching(self):
        original = mw.i18n.current_language
        try:
            mw.i18n.set_language("ru")
            self.assertEqual(mw.i18n.get("exiting"), "Выход...")
            self.assertEqual(mw.i18n.toggle_language(), "en")
            mw.i18n.set_language("unknown")
            self.assertEqual(mw.i18n.current_language, "en")
        finally:
            mw.i18n.set_language(original)

    def test_menu_labels_fit_the_frame(self):
        for language in ("en", "ru"):
            mw.i18n.set_language(language)
            try:
                for spec in mw.get_heuristics():
                    self.assertLessEqual(len(spec[0]), mw.MENU_WIDTH)
                for key in (
                    "menu_extract",
                    "menu_decrypt",
                    "menu_info",
                    "menu_switch_lang",
                    "menu_exit",
                ):
                    self.assertLessEqual(len(mw.i18n.get(key)), mw.MENU_WIDTH - 6)
                for key in (
                    "extract_title",
                    "decrypt_title",
                    "info_title",
                    "metadata_info_title",
                ):
                    self.assertLessEqual(len(mw.i18n.get(key)), mw.BOX_WIDTH - 2)
            finally:
                mw.i18n.set_language("en")


class TestOutput(unittest.TestCase):
    def test_write_output_creates_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            target = os.path.join(folder, "a", "b", "out.dat")
            written = mw.write_output(b"payload", target, "fallback.dat")
            self.assertEqual(written, target)
            with open(written, "rb") as handle:
                self.assertEqual(handle.read(), b"payload")

    def test_write_output_uses_default_name_for_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            written = mw.write_output(b"x", folder, "fallback.dat")
            self.assertEqual(written, os.path.join(folder, "fallback.dat"))

    def test_paint_contains_reset(self):
        painted = mw.paint("text", mw.COLOR_ERROR, True)
        self.assertTrue(painted.endswith(mw.Style.RESET_ALL))
        self.assertIn(mw.COLOR_ERROR, painted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
