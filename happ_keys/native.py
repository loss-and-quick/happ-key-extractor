"""Unicorn-based ARM64 emulator for liberror-code.so JNI extraction."""

from __future__ import annotations

import os
import struct
from typing import Any

from unicorn import (
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_MODE_LITTLE_ENDIAN,
    UC_PROT_ALL,
    Uc,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
)


class UnsupportedCodeShapeError(Exception):
    """Raised when the JNI export or epilogue does not match the expected pattern."""


class UnicornNativeDumper:
    """Loads and emulates ARM64 liberror-code.so to dump decrypted error strings."""

    BASE: int = 0x10000000
    TRAMPOLINE_BASE: int = 0x20000000
    HEAP_BASE: int = 0x30000000
    TLS_BASE: int = 0x40000000
    STACK_BASE: int = 0x70000000
    RETURN_ADDR: int = 0x80000000

    TARGET_SYMBOLS: tuple[str, ...] = (
        "Java_su_happ_proxyutility_util_ErrorCodeJNIWrapper_jniGetErrorMessageFromCode",
        "Java_com_happproxy_util_ErrorCodeJNIWrapper_jniGetErrorMessageFromCode",
    )

    def __init__(self, so_bytes: bytes) -> None:
        self.raw_data = bytearray(so_bytes)
        self.discovered_entry_vaddr: int | None = None
        self.discovered_target_vaddr: int | None = None
        self.discovered_patch_offset: int | None = None
        self.load_segments: list[tuple[int, int, int]] = []
        self.dyn_info: dict[int, int] = {}
        self.symtab_off: int = 0
        self.strtab_off: int = 0
        self.strsz: int = 0

        self._parse_elf()
        self._find_and_patch_site()
        self._init_emulator()

    def _v2f(self, vaddr: int) -> int:
        for p_vaddr, p_filesz, p_offset in self.load_segments:
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return vaddr

    def _parse_elf(self) -> None:
        e_phoff = struct.unpack_from("<Q", self.raw_data, 32)[0]
        e_phnum = struct.unpack_from("<H", self.raw_data, 56)[0]

        dyn_offset = 0
        dyn_sz = 0
        for i in range(e_phnum):
            ph = self.raw_data[e_phoff + i * 56 : e_phoff + (i + 1) * 56]
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack("<IIQQQQQQ", ph)
            if p_type == 1:  # PT_LOAD
                self.load_segments.append((p_vaddr, p_filesz, p_offset))
            elif p_type == 2:  # PT_DYNAMIC
                dyn_offset, dyn_sz = p_offset, p_filesz

        for j in range(0, dyn_sz, 16):
            tag, val = struct.unpack("<qQ", self.raw_data[dyn_offset + j : dyn_offset + j + 16])
            if tag == 0:
                break
            self.dyn_info[tag] = val

        self.symtab_off = self._v2f(self.dyn_info.get(6, 0))  # DT_SYMTAB
        self.strtab_off = self._v2f(self.dyn_info.get(5, 0))  # DT_STRTAB
        self.strsz = self.dyn_info.get(10, 0)  # DT_STRSZ

    def _find_symbol(self, name: str) -> int | None:
        for s_i in range(self.symtab_off, self.strtab_off, 24):
            st_name, _, _, _, st_val, _ = struct.unpack("<IBBHQQ", self.raw_data[s_i : s_i + 24])
            if st_name < self.strsz:
                null_pos = self.raw_data.find(b"\x00", self.strtab_off + st_name)
                sym = self.raw_data[self.strtab_off + st_name : null_pos].decode("ascii", errors="ignore")
                if sym == name:
                    return st_val
        return None

    def _find_and_patch_site(self) -> None:
        # 1. Resolve exported symbol
        for sym_name in self.TARGET_SYMBOLS:
            vaddr = self._find_symbol(sym_name)
            if vaddr is not None:
                self.discovered_entry_vaddr = vaddr
                break

        if self.discovered_entry_vaddr is None:
            raise UnsupportedCodeShapeError("ErrorCodeJNIWrapper_jniGetErrorMessageFromCode symbol not found")

        # 2. Follow `b <target>` thunk
        entry_vaddr = self.discovered_entry_vaddr
        thunk_file_off = self._v2f(entry_vaddr)
        thunk_ins = struct.unpack_from("<I", self.raw_data, thunk_file_off)[0]
        # ARM64 branch opcode: bits 26-31 == 000101 (0x14)
        if (thunk_ins >> 26) != 0x05:
            # Maybe already the function entry directly
            self.discovered_target_vaddr = entry_vaddr
        else:
            imm26 = thunk_ins & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000  # sign-extend
            self.discovered_target_vaddr = entry_vaddr + imm26 * 4

        target_vaddr = self.discovered_target_vaddr
        assert target_vaddr is not None
        target_file_off = self._v2f(target_vaddr)

        # 3. Search for the epilogue patch pattern
        # Shape 4.7.1:
        # ldr x8, [x19]          -> 0xf9400268
        # ldr x2, [x8, #0x538]   -> 0xf9429d02
        # mov x0, x19            -> 0xaa1303e0
        # ldp x20, x19, [sp,#10] -> 0xa9414fe4
        # ldp x29, x30, [sp],#20 -> 0xa8c27bfd
        # br  x2                 -> 0xd61f0040
        found_off = None
        search_limit = min(len(self.raw_data) - 24, target_file_off + 0x8000)

        for pos in range(target_file_off, search_limit, 4):
            w = struct.unpack_from("<I", self.raw_data, pos)[0]
            if w == 0xF9429D02:  # ldr x2, [x8, #0x538]
                w_prev = struct.unpack_from("<I", self.raw_data, pos - 4)[0]
                if w_prev == 0xF9400268:  # ldr x8, [x19]
                    found_off = pos - 4
                    break

        if found_off is None:
            # Generalized search: any ldr xN,[xM,#imm] where imm is a multiple of 8 and <= 0x6b0,
            # followed within a few instructions by br xN
            for pos in range(target_file_off, search_limit, 4):
                w = struct.unpack_from("<I", self.raw_data, pos)[0]
                # Check if w is ldr xN, [xM, #imm]
                # 64-bit ldr (imm): 11 111 001 01 <imm12> <Rn> <Rt>
                if (w >> 22) == 0x3E5:
                    rt = w & 0x1F
                    imm12 = (w >> 10) & 0xFFF
                    imm = imm12 * 8
                    if imm <= 0x6B0 and imm % 8 == 0:
                        # Look ahead up to 6 instructions for br xN (0xd61f0000 | (rt << 5))
                        br_ins = 0xD61F0000 | (rt << 5)
                        for look in range(pos + 4, min(pos + 28, search_limit), 4):
                            if struct.unpack_from("<I", self.raw_data, look)[0] == br_ins:
                                # Candidate found
                                found_off = pos - 4
                                break
                    if found_off is not None:
                        break

        if found_off is None:
            target_str = hex(target_vaddr) if self.discovered_target_vaddr is not None else "unknown"
            raise UnsupportedCodeShapeError(f"liberror-code.so epilogue pattern not found in target at {target_str}")

        self.discovered_patch_offset = found_off

        # Patch:
        # +0: mov x0, x1
        # +4: nop
        # +8: nop
        # +20: ret
        struct.pack_into("<I", self.raw_data, found_off, 0xAA0103E0)  # mov x0, x1
        struct.pack_into("<I", self.raw_data, found_off + 4, 0xD503201F)  # nop
        struct.pack_into("<I", self.raw_data, found_off + 8, 0xD503201F)  # nop
        struct.pack_into("<I", self.raw_data, found_off + 20, 0xD65F03C0)  # ret

    def _init_emulator(self) -> None:
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)

        # 1. Map library region and write segments
        self.mu.mem_map(self.BASE, 0x500000, UC_PROT_ALL)
        for p_vaddr, p_filesz, p_offset in self.load_segments:
            self.mu.mem_write(self.BASE + p_vaddr, bytes(self.raw_data[p_offset : p_offset + p_filesz]))

        # 2. Map stack, heap, TLS, trampolines, return page
        self.mu.mem_map(self.STACK_BASE, 0x100000, UC_PROT_ALL)
        self.mu.mem_map(self.HEAP_BASE, 0x2000000, UC_PROT_ALL)
        self.mu.mem_map(self.TLS_BASE, 0x10000, UC_PROT_ALL)
        self.mu.mem_map(self.TRAMPOLINE_BASE, 0x10000, UC_PROT_ALL)
        self.mu.mem_map(self.RETURN_ADDR, 0x10000, UC_PROT_ALL)
        self.mu.mem_write(self.RETURN_ADDR, b"\x1f\x20\x03\xd5")  # nop

        # Fill trampoline area with `ret` instructions (0xd65f03c0)
        ret_ins = struct.pack("<I", 0xD65F03C0)
        self.mu.mem_write(self.TRAMPOLINE_BASE, ret_ins * (0x10000 // 4))

        # 3. Stack canary in TLS at +0x28
        canary = struct.unpack("<Q", os.urandom(8))[0]
        self.mu.mem_write(self.TLS_BASE + 0x28, struct.pack("<Q", canary))

        # 4. ARM64 assembly stub for pthread_once at TRAMPOLINE_BASE + 0x8000
        # Preserves LR on stack, checks control word, calls init via blr x1, restores LR, returns 0.
        pthread_once_addr = self.TRAMPOLINE_BASE + 0x8000
        words = [
            0xA9BE7BFD,  # stp x29, x30, [sp, #-0x20]!
            0x910003FD,  # mov x29, sp
            0xB9400002,  # ldr w2, [x0]
            0x35000082,  # cbnz w2, +16 (to mov w0, #0)
            0x52800022,  # mov w2, #1
            0xB9000002,  # str w2, [x0]
            0xD63F0020,  # blr x1
            0x52800000,  # mov w0, #0
            0xA8C27BFD,  # ldp x29, x30, [sp], #0x20
            0xD65F03C0,  # ret
        ]
        self.mu.mem_write(pthread_once_addr, b"".join(struct.pack("<I", w) for w in words))

        # 5. Parse relocations (.rela.dyn and .rela.plt)
        rela_dyn_off = self.dyn_info.get(7, 0)
        rela_dyn_sz = self.dyn_info.get(8, 0)
        rela_plt_off = self.dyn_info.get(23, 0)
        rela_plt_sz = self.dyn_info.get(2, 0)

        def get_sym_name(sym_idx: int) -> str:
            if sym_idx == 0:
                return ""
            st_name = struct.unpack_from("<I", self.raw_data, self.symtab_off + sym_idx * 24)[0]
            s = self.raw_data[self.strtab_off + st_name :]
            null_pos = s.find(b"\x00")
            return s[:null_pos].decode("ascii", errors="ignore")

        self.sym_to_slot: dict[str, int] = {}
        self.slot_to_sym: dict[int, str] = {}
        next_slot = 0

        for off_v, sz in [(rela_dyn_off, rela_dyn_sz), (rela_plt_off, rela_plt_sz)]:
            off = self._v2f(off_v)
            for j in range(0, sz, 24):
                r_offset, r_info, r_addend = struct.unpack("<QQq", self.raw_data[off + j : off + j + 24])
                r_type = r_info & 0xFFFFFFFF
                r_sym = r_info >> 32

                if r_type == 1027:  # R_AARCH64_RELATIVE
                    self.mu.mem_write(self.BASE + r_offset, struct.pack("<Q", self.BASE + r_addend))
                elif r_type in (257, 1025, 1026):  # ABS64, GLOB_DAT, JUMP_SLOT
                    name = get_sym_name(r_sym)
                    if name == "pthread_once":
                        trampoline_addr = pthread_once_addr
                    else:
                        if name not in self.sym_to_slot:
                            slot_addr = self.TRAMPOLINE_BASE + next_slot * 16
                            self.sym_to_slot[name] = slot_addr
                            self.slot_to_sym[slot_addr] = name
                            next_slot += 1
                        trampoline_addr = self.sym_to_slot[name]
                    self.mu.mem_write(self.BASE + r_offset, struct.pack("<Q", trampoline_addr))

        # 6. Shim runtime state
        self.heap_ptr = self.HEAP_BASE
        self.allocations: dict[int, int] = {}
        self.tls_keys: dict[int, int] = {}
        self.next_tls_key = 1

        # Hook only the trampoline dispatch range [0x20000000, 0x20007fff],
        # leaving the pthread_once assembly stub at 0x20008000 to execute unhooked!
        self.mu.hook_add(
            UC_HOOK_CODE,
            self._hook_trampoline,
            begin=self.TRAMPOLINE_BASE,
            end=self.TRAMPOLINE_BASE + 0x7FFF,
        )

    def _hook_trampoline(self, uc: Uc, address: int, size: int, user_data: Any) -> None:
        sym = self.slot_to_sym.get(address)
        if not sym:
            return

        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        res = 0

        if sym == "malloc":
            sz = (x0 + 15) & ~15
            res = self.heap_ptr
            self.heap_ptr += sz
            self.allocations[res] = x0
        elif sym == "calloc":
            tot = x0 * x1
            sz = (tot + 15) & ~15
            res = self.heap_ptr
            self.heap_ptr += sz
            self.allocations[res] = tot
            uc.mem_write(res, b"\x00" * tot)
        elif sym == "realloc":
            if x0 == 0:
                sz = (x1 + 15) & ~15
                res = self.heap_ptr
                self.heap_ptr += sz
                self.allocations[res] = x1
            elif x1 == 0:
                res = 0
            else:
                old_sz = self.allocations.get(x0, x1)
                sz = (x1 + 15) & ~15
                res = self.heap_ptr
                self.heap_ptr += sz
                self.allocations[res] = x1
                copy_len = min(old_sz if old_sz is not None else x1, x1)
                old_data = uc.mem_read(x0, copy_len)
                uc.mem_write(res, bytes(old_data))
        elif sym == "free":
            res = 0
        elif sym in ("memcpy", "memmove"):
            if x2 > 0:
                uc.mem_write(x0, bytes(uc.mem_read(x1, x2)))
            res = x0
        elif sym == "memset":
            if x2 > 0:
                uc.mem_write(x0, bytes([x1 & 0xFF]) * x2)
            res = x0
        elif sym == "strlen":
            length = 0
            while uc.mem_read(x0 + length, 1)[0] != 0:
                length += 1
            res = length
        elif sym == "strcmp":
            str1 = bytearray()
            while True:
                b = uc.mem_read(x0 + len(str1), 1)[0]
                if b == 0:
                    break
                str1.append(b)
            str2 = bytearray()
            while True:
                b = uc.mem_read(x1 + len(str2), 1)[0]
                if b == 0:
                    break
                str2.append(b)
            res = 0 if str1 == str2 else (1 if str1 > str2 else -1)
        elif sym == "strncmp":
            str1 = bytearray()
            for i in range(x2):
                b = uc.mem_read(x0 + i, 1)[0]
                if b == 0:
                    break
                str1.append(b)
            str2 = bytearray()
            for i in range(x2):
                b = uc.mem_read(x1 + i, 1)[0]
                if b == 0:
                    break
                str2.append(b)
            res = 0 if str1 == str2 else (1 if str1 > str2 else -1)
        elif sym == "memcmp":
            b1 = bytes(uc.mem_read(x0, x2)) if x2 > 0 else b""
            b2 = bytes(uc.mem_read(x1, x2)) if x2 > 0 else b""
            res = 0 if b1 == b2 else (1 if b1 > b2 else -1)
        elif sym == "pthread_key_create":
            k = self.next_tls_key
            self.next_tls_key += 1
            uc.mem_write(x0, struct.pack("<I", k))
            self.tls_keys[k] = 0
            res = 0
        elif sym == "pthread_setspecific":
            self.tls_keys[x0] = x1
            res = 0
        elif sym == "pthread_getspecific":
            res = self.tls_keys.get(x0, 0)
        elif (
            sym in ("pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_init")
            or sym.startswith("pthread_rwlock_")
            or sym.startswith("pthread_cond_")
            or sym
            in (
                "__cxa_thread_atexit_impl",
                "__cxa_atexit",
                "__cxa_finalize",
                "__register_atfork",
            )
        ):
            res = 0
        elif sym == "abort":
            raise RuntimeError("abort() called by guest library")
        elif sym == "__stack_chk_fail":
            raise RuntimeError("__stack_chk_fail() called: stack canary corrupted")
        else:
            raise RuntimeError(f"Unhandled libc/pthread symbol: {sym}")

        uc.reg_write(UC_ARM64_REG_X0, res)

    def get_string(self, code: int) -> str:
        """Call patched jniGetErrorMessageFromCode with given error code and return string."""
        if self.discovered_target_vaddr is None:
            raise RuntimeError("Target address not discovered")

        sp = self.STACK_BASE + 0x80000
        self.mu.reg_write(UC_ARM64_REG_SP, sp)
        self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, self.TLS_BASE)
        self.mu.reg_write(UC_ARM64_REG_X0, 0x12340000)  # fake JNIEnv*
        self.mu.reg_write(UC_ARM64_REG_X1, 0)  # fake jobject thiz
        self.mu.reg_write(UC_ARM64_REG_X2, code)  # integer error code
        self.mu.reg_write(UC_ARM64_REG_LR, self.RETURN_ADDR)

        self.mu.emu_start(self.BASE + self.discovered_target_vaddr, self.RETURN_ADDR, timeout=3000000)

        str_ptr = self.mu.reg_read(UC_ARM64_REG_X0)
        if str_ptr == 0:
            return ""

        buf = bytearray()
        while True:
            b = self.mu.mem_read(str_ptr + len(buf), 1)[0]
            if b == 0:
                break
            buf.append(b)

        return buf.decode("utf-8", errors="replace")
