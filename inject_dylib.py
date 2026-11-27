#!/usr/bin/env python3
"""
inject_dylib.py - 往 Mach-O 主二进制注入 LC_LOAD_DYLIB (arm64 iOS)
用法: python3 inject_dylib.py <WeChat 二进制> <dylib 路径> <install_name>
  例: python3 inject_dylib.py WeChat libvipbypass.dylib @rpath/libvipbypass.dylib

原理:
  1) 备份原二进制
  2) 在 load commands 区插入 LC_LOAD_DYLIB (固定 8 + 12 + name len, 8 字节对齐)
     和 LC_RPATH (8 + 16 + rpath len, 对齐) -> @executable_path/Frameworks
  3) ncmds += 2, sizeofcmds += (两命令对齐后总长)
  4) 因 load commands 紧跟 header, 插入会让其后所有字节 (包括 __LINKEDIT 数据) 下移。
     我们把插入放在 "sizeofcmds 末尾" 而不是 header 后, 避免移动段数据:
     实际上 load commands 必须连续在 header 后。插入 = 把 [old_end..new_end) 的字节
     右移。但段数据(fileoff) 不依赖 load command 区, 只 LINKEDIT 在文件尾部,
     插入在 header 后会把 LINKEDIT 之后的偏移推后 -> 需同步改 __LINKEDIT 段 fileoff.
     本 patcher 只在 load commands 区尾部追加(即整体右移), 并重写所有段的 fileoff
     与 symtab/stab 偏移, 保证一致性。

注意: 该操作需 macOS + codesign 重签(Windows 无法签名 iOS 包). 本脚本产出 patch 后的
二进制, 在 macOS 上 codesign --force --deep --sign - 后打包.
"""
import struct, sys, shutil, os

def align8(v): return (v + 7) & ~7

def main():
    exe, dylib_path, install_name = sys.argv[1], sys.argv[2], sys.argv[3]
    bak = exe + ".orig"
    if not os.path.exists(bak):
        shutil.copy2(exe, bak)

    data = bytearray(open(exe, "rb").read())
    magic = struct.unpack_from("<I", data, 0)[0]
    assert magic == 0xFEEDFACF, hex(magic)

    # 解析现有 load commands
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    lc_start = 32
    # 收集所有段的 fileoff (用于后续右移修正)
    segs = []
    pos = lc_start
    for i in range(ncmds):
        cmd, csize = struct.unpack_from("<II", data, pos)
        if cmd in (0x19, 0x1F, 0x0C):  # segment / segment_64 / segment
            segname = data[pos+8:pos+24].split(b"\x00")[0].decode(errors="replace")
            # 64-bit segment layout (本二进制是 segment_64, cmd 0x19)
            if csize >= 120:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, pos+24)
            else:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", data, pos+24)
            segs.append([segname, vmaddr, vmsize, fileoff, filesize, cmd])
        pos += csize

    # 构建要插入的 load commands
    # LC_RPATH: cmd(4) csize(4) locp(4) path[...]; csize 对齐 4
    # LC_RPATH: cmd(4) csize(4) locp(4) path[...] ; locp = path 在结构内的偏移 = 12
    # csize = 12 + len(path), 按 8 对齐
    rpath = b"@executable_path/Frameworks\x00"
    rpath_csize = align8(12 + len(rpath))
    lc_rpath_body = struct.pack("<III", 0x1C, rpath_csize, 12) + rpath
    lc_rpath = lc_rpath_body + b"\x00"*(rpath_csize - len(lc_rpath_body))
    assert len(lc_rpath) == rpath_csize, (len(lc_rpath), rpath_csize)

    # LC_LOAD_DYLIB: cmd(4) csize(4) timestamp(4) curfileoff(4) installname offset; name at +24
    dylib_name = install_name.encode() + b"\x00"
    # LC_LOAD_DYLIB: cmd(4) csize(4) timestamp(4) curpathoff(4) installnameoff(4) name[...]
    # installname 偏移 = 5*4 = 20
    lc_load_csize = align8(20 + len(dylib_name))
    lc_load_body = struct.pack("<IIIII", 0x08, lc_load_csize, 0, 0, 20) + dylib_name
    lc_load = lc_load_body + b"\x00"*(lc_load_csize - len(lc_load_body))
    assert len(lc_load) == lc_load_csize

    insert = lc_rpath + lc_load
    insert_len = len(insert)

    # 在 lc_start 之后, 现有命令之前插入 -> 现有命令整体右移 insert_len
    # 新二进制 = data[:lc_start] + insert + data[lc_start:]
    # 但这样会移动所有 load command 之后的字节, 包括 __LINKEDIT 与段数据 (若 fileoff > lc_start)
    # 段的 fileoff 通常 >= sizeofcmds+32, 会受影响. 我们把所有 fileoff > lc_start 的段,
    # 以及 symtab/stab, 的 fileoff 加 insert_len.
    new = data[:lc_start] + insert + data[lc_start:]

    # 修正 header
    struct.pack_into("<I", new, 16, ncmds + 2)        # ncmds
    struct.pack_into("<I", new, 20, sizeofcmds + insert_len)  # sizeofcmds

    # 修正段 fileoff (在 lc_start 之后的段数据要 +insert_len)
    # 重新在新二进制里解析段, 对其 fileoff >= sizeofcmds_old+32 的加 insert_len
    pos = lc_start + insert_len
    for i in range(ncmds):  # 原 ncmds 条
        cmd, csize = struct.unpack_from("<II", new, pos)
        if cmd in (0x19, 0x1F):  # segment_64
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", new, pos+24)
            if fileoff >= (lc_start):  # 段数据在 load cmd 区之后
                newfileoff = fileoff + insert_len
                struct.pack_into("<Q", new, pos+40, newfileoff)  # fileoff at pos+40 for seg64
            # sections within: fix each section fileoff
            nsects = (csize - 72) // 80
            so = pos + 72
            for s in range(nsects):
                saddr, ssize = struct.unpack_from("<QQ", new, so+32)
                sfileoff = struct.unpack_from("<Q", new, so+56)[0]
                if sfileoff >= lc_start:
                    struct.pack_into("<Q", new, so+56, sfileoff + insert_len)
                so += 80
        pos += csize

    # 修正 symtab / stab (LC_SYMTAB, LC_STABS) fileoff
    pos = lc_start + insert_len
    for i in range(ncmds):
        cmd, csize = struct.unpack_from("<II", new, pos)
        if cmd == 0x02:  # LC_SYMTAB: symoff(4) nsyms(4) stroff(4) strsize(4) at +8
            symoff = struct.unpack_from("<I", new, pos+8)[0]
            stroff = struct.unpack_from("<I", new, pos+16)[0]
            if symoff >= lc_start: struct.pack_into("<I", new, pos+8, symoff + insert_len)
            if stroff >= lc_start: struct.pack_into("<I", new, pos+16, stroff + insert_len)
        if cmd == 0x09:  # LC_STABS: stoff(4)
            stoff = struct.unpack_from("<I", new, pos+8)[0]
            if stoff >= lc_start: struct.pack_into("<I", new, pos+8, stoff + insert_len)
        pos += csize

    open(exe, "wb").write(new)
    print(f"[+] injected LC_LOAD_DYLIB ({install_name}) + LC_RPATH")
    print(f"[+] ncmds {ncmds}->{ncmds+2}, sizeofcmds {sizeofcmds}->{sizeofcmds+insert_len}")
    print(f"[+] backup at {bak}")
    print("[!] 下一步 (macOS):")
    print(f"    cp {dylib_path} <app>/Frameworks/libvipbypass.dylib")
    print(f"    codesign --force --sign - <app>/Frameworks/libvipbypass.dylib")
    print(f"    codesign --force --deep --sign - <app>")
    print(f"    # 重新打包 .ipa, TrollStore 安装")

if __name__ == "__main__":
    main()
