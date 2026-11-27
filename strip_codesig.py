#!/usr/bin/env python3
"""
strip_codesig.py - 删掉 Mach-O 里的 LC_CODE_SIGNATURE load command,
让 TrollStore / codesign 重签时生成新签名.
注入 load command 后 __LINKEDIT 偏移变了, 原 code signature blob 错位,
amfid 解析失败导致 Parse Error. 先 strip 掉旧签名, 重签时自动补新的.
用法: python3 strip_codesig.py <Mach-O 二进制>
"""
import struct, sys, shutil

path = sys.argv[1]
d = bytearray(open(path, "rb").read())
magic = struct.unpack_from("<I", d, 0)[0]
assert magic == 0xFEEDFACF, hex(magic)
ncmds, sizeofcmds = struct.unpack_from("<II", d, 16)
print("ncmds", ncmds, "sizeofcmds 0x%x" % sizeofcmds)

LC_CODE_SIGNATURE = 0x1D
# 找出所有 LC_CODE_SIGNATURE 的 (off, csize)
targets = []
pos = 32
for i in range(ncmds):
    cmd, csize = struct.unpack_from("<II", d, pos)
    if cmd == LC_CODE_SIGNATURE:
        targets.append((i, pos, csize))
        codeoff, codesize = struct.unpack_from("<II", d, pos+8)
        print("found LC_CODE_SIGNATURE @cmd %d fileoff 0x%x csize %d codeoff 0x%x codesize 0x%x"
              % (i, pos, csize, codeoff, codesize))
    pos += csize

if not targets:
    print("no LC_CODE_SIGNATURE; nothing to strip")
    sys.exit(0)

# 策略: 把每个 LC_CODE_SIGNATURE 的 cmd 改成 LC_NOOP(0x64) 并保留 csize (占位),
# 或直接删除 (需重建 ncmds/sizeofcmds 并移动后续 load command).
# 简化且安全: 改成 LC_NOOP, csize 不变, 不影响后续 load command 偏移 (无需移动字节).
for i, pos, csize in targets:
    struct.pack_into("<I", d, pos, 0x64)  # cmd = LC_NOOP
    # csize 保持原值 (LC_NOOP 通常 csize=8, 但这里保留原 csize 以不破坏 load cmd 区布局)
    print("  -> cmd %d patched to LC_NOOP (csize kept %d)" % (i, csize))

open(path, "wb").write(d)
print("[+] stripped LC_CODE_SIGNATURE -> LC_NOOP. 重签时 codesign/TrollStore 会补新签名.")
