#!/usr/bin/env python3
"""
inject_beauty.py - 把 wechat_beauty_loader.dylib 注入到微信主二进制
用法: python inject_beauty.py <WeChat主二进制> <loader.dylib路径>
"""
import struct, sys, shutil, os

def align8(v): return (v + 7) & ~7

def main():
    exe = sys.argv[1]
    dylib_path = sys.argv[2]
    install_name = "@executable_path/Frameworks/wechat_beauty_loader.dylib"
    
    bak = exe + ".orig"
    if not os.path.exists(bak):
        shutil.copy2(exe, bak)
    
    data = bytearray(open(exe, "rb").read())
    magic = struct.unpack_from("<I", data, 0)[0]
    assert magic == 0xFEEDFACF, hex(magic)
    
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    lc_start = 32
    
    # 收集所有段的 fileoff
    segs = []
    pos = lc_start
    for i in range(ncmds):
        cmd, csize = struct.unpack_from("<II", data, pos)
        if cmd in (0x19, 0x1F):
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, pos+24)
            segs.append([vmaddr, vmsize, fileoff, filesize, cmd])
        pos += csize
    
    # 构建 load commands
    rpath = b"@executable_path/Frameworks\x00"
    rpath_csize = align8(12 + len(rpath))
    lc_rpath_body = struct.pack("<III", 0x1C, rpath_csize, 12) + rpath
    lc_rpath = lc_rpath_body + b"\x00"*(rpath_csize - len(lc_rpath_body))
    
    dylib_name = install_name.encode() + b"\x00"
    lc_load_csize = align8(20 + len(dylib_name))
    lc_load_body = struct.pack("<IIIII", 0x08, lc_load_csize, 0, 0, 20) + dylib_name
    lc_load = lc_load_body + b"\x00"*(lc_load_csize - len(lc_load_body))
    
    insert = lc_rpath + lc_load
    insert_len = len(insert)
    
    # 插入
    new = data[:lc_start] + insert + data[lc_start:]
    
    # 修正 header
    struct.pack_into("<I", new, 16, ncmds + 2)
    struct.pack_into("<I", new, 20, sizeofcmds + insert_len)
    
    # 修正段 fileoff
    pos = lc_start + insert_len
    for i in range(ncmds):
        cmd, csize = struct.unpack_from("<II", new, pos)
        if cmd in (0x19, 0x1F):
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", new, pos+24)
            if fileoff >= lc_start:
                newfileoff = fileoff + insert_len
                struct.pack_into("<Q", new, pos+40, newfileoff)
            nsects = (csize - 72) // 80
            so = pos + 72
            for s in range(nsects):
                saddr, ssize = struct.unpack_from("<QQ", new, so+32)
                sfileoff = struct.unpack_from("<Q", new, so+56)[0]
                if sfileoff >= lc_start:
                    struct.pack_into("<Q", new, so+56, sfileoff + insert_len)
                so += 80
        pos += csize
    
    # 修正 symtab/stab
    pos = lc_start + insert_len
    for i in range(ncmds):
        cmd, csize = struct.unpack_from("<II", new, pos)
        if cmd == 0x02:
            symoff = struct.unpack_from("<I", new, pos+8)[0]
            stroff = struct.unpack_from("<I", new, pos+16)[0]
            if symoff >= lc_start: struct.pack_into("<I", new, pos+8, symoff + insert_len)
            if stroff >= lc_start: struct.pack_into("<I", new, pos+16, stroff + insert_len)
        if cmd == 0x09:
            stoff = struct.unpack_from("<I", new, pos+8)[0]
            if stoff >= lc_start: struct.pack_into("<I", new, pos+8, stoff + insert_len)
        pos += csize
    
    open(exe, "wb").write(new)
    print(f"[+] injected LC_LOAD_DYLIB {install_name} + LC_RPATH")
    print(f"[+] ncmds {ncmds}->{ncmds+2}, sizeofcmds {sizeofcmds}->{sizeofcmds+insert_len}")
    print(f"[+] backup at {bak}")

if __name__ == "__main__":
    main()
