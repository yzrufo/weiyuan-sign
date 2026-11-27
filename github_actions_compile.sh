#!/bin/bash
# GitHub Actions macOS runner: 编译 vipbypass.dylib + 注入 + 签名 + 打 ipa
# 仓库里: b000..b014 (原始主二进制 35MB 块) + rest001.. (资源分卷, 含 vipbypass_src/vipbypass.m)
set -euo pipefail
WS="$GITHUB_WORKSPACE"
cd "$WS"

echo "=== [1/6] 拼回原始主二进制 (o000..o014) ==="
ls o0* | sort | xargs -I{} cat {} > WeChat_orig
ls -lh WeChat_orig
echo "size=$(wc -c < WeChat_orig)"

echo "=== [2/6] 解压资源分卷 (r001..r015, 跳过空卷) ==="
mkdir -p Payload/WeChat.app
for z in r0*.zip; do
  [ -s "$z" ] && unzip -o -q "$z" -d . || echo "  skip empty $z"
done
[ -f "Payload/WeChat.app/vipbypass_src/vipbypass.m" ] || { echo "缺 vipbypass.m"; exit 1; }
echo "资源解压 OK, vipbypass.m 在"

echo "=== [3/6] 编译 vipbypass.dylib (arm64 iOS) ==="
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
cp WeChat_orig "Payload/WeChat.app/WeChat"
clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=12.0 \
  -fobjc-arc -dynamiclib -framework Foundation -framework UIKit -lobjc \
  "Payload/WeChat.app/vipbypass_src/vipbypass.m" -o "Payload/WeChat.app/Frameworks/vipbypass.dylib"
ls -lh "Payload/WeChat.app/Frameworks/vipbypass.dylib"

echo "=== [4/6] 注入主二进制 + strip 旧签名 ==="
# 需要 inject_dylib.py + strip_codesig.py (也在 rest 里, 放 app 根)
python3 - <<'PYEOF'
# 内联注入逻辑 (避免依赖外部 py 文件), 直接 patch WeChat
import struct, shutil, os
exe = "Payload/WeChat.app/WeChat"
bak = exe + ".orig2"
if not os.path.exists(bak): shutil.copy2(exe, bak)
data = bytearray(open(exe, "rb").read())
TEXT_BASE = 0x100000000
ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
def align8(v): return (v+7) & ~7
LC_LOAD_DYLIB=0x08; LC_RPATH=0x1C
name = b"@rpath/vipbypass.dylib"
rpath = b"@executable_path/Frameworks"
dylib_lc = struct.pack("<III", LC_LOAD_DYLIB, align8(20+len(name)+1), 0) + struct.pack("<I", 20) + struct.pack("<I", 0)
# LC_LOAD_DYLIB: cmd csize timestamp curpathoff installnameoff(=20) name
dylib_lc = struct.pack("<IIII", LC_LOAD_DYLIB, align8(20+len(name)+1), 0, 0) + struct.pack("<I", 20) + name + b"\x00"
rpath_lc = struct.pack("<II", LC_RPATH, align8(12+len(rpath))) + struct.pack("<I", 12) + rpath + b"\x00"
ins = dylib_lc + rpath_lc
# 在 load commands 区末尾追加 (header 后, 32 + sizeofcmds 处)
lc_end = 32 + sizeofcmds
newdata = data[:lc_end] + ins + data[lc_end:]
# 同步 fileoff: 所有段/段节的 fileoff >= lc_end 的 + len(ins); LC_SYMTAB symoff/stroff, LC_STABS stoff
SHIFT = len(ins)
# 重新解析 header, patch 受影响 load commands
import copy
pos = 32 + sizeofcmds  # 新 load cmd 区起点 (追加在末尾, 原 load cmd 不动)
# 追加在末尾, 原 load commands 偏移不变, 只需改 ncmds/sizeofcmds + 段 fileoff + symtab
# 但段 fileoff 是绝对文件偏移, 追加 load cmd 会把段数据整体右移 SHIFT -> 所有 fileoff >= lc_end 的 +SHIFT
# 重新遍历 load commands (原区)
p2 = 32
for i in range(ncmds):
    cmd, csize = struct.unpack_from("<II", newdata, p2)
    if csize < 8: break
    if cmd == 0x19:  # segment_64 (本二进制用 0x19)
        segname = newdata[p2+8:p2+24].split(b"\x00")[0].decode(errors="replace")
        nsects = (csize - 72) // 80
        # 段 fileoff
        foff = struct.unpack_from("<Q", newdata, p2+40)[0]
        if foff >= lc_end:
            struct.pack_into("<Q", newdata, p2+40, foff + SHIFT)
        so = p2 + 72
        for s in range(nsects):
            soff = struct.unpack_from("<Q", newdata, so+56)[0]
            if soff >= lc_end:
                struct.pack_into("<Q", newdata, so+56, soff + SHIFT)
            so += 80
    elif cmd == 0x2C:  # LC_SYMTAB
        symoff, = struct.unpack_from("<I", newdata, p2+16)
        stroff, = struct.unpack_from("<I", newdata, p2+24)
        if symoff >= lc_end: struct.pack_into("<I", newdata, p2+16, symoff+SHIFT)
        if stroff >= lc_end: struct.pack_into("<I", newdata, p2+24, stroff+SHIFT)
    elif cmd == 0x6C:  # LC_STABS
        stoff, = struct.unpack_from("<I", newdata, p2+8)
        if stoff >= lc_end: struct.pack_into("<I", newdata, p2+8, stoff+SHIFT)
    p2 += csize
# ncmds += 2, sizeofcmds += SHIFT
struct.pack_into("<I", newdata, 16, ncmds+2)
struct.pack_into("<I", newdata, 20, sizeofcmds+SHIFT)
open(exe, "wb").write(newdata)
print("[+] injected LC_LOAD_DYLIB @rpath/vipbypass.dylib + LC_RPATH")

# strip LC_CODE_SIGNATURE -> LC_NOOP
data2 = bytearray(open(exe,"rb").read())
n2, sc2 = struct.unpack_from("<II", data2, 16)
p3 = 32
for i in range(n2):
    cmd, csize = struct.unpack_from("<II", data2, p3)
    if csize < 8: break
    if cmd == 0x1D:
        struct.pack_into("<I", data2, p3, 0x64)
        print("[+] stripped LC_CODE_SIGNATURE -> LC_NOOP")
    p3 += csize
open(exe, "wb").write(data2)
PYEOF

echo "=== [5/6] 签名 ==="
APP="Payload/WeChat.app"
codesign --force --sign - "$APP/Frameworks/vipbypass.dylib"
for fw in "$APP"/Frameworks/*.framework; do
  [ -e "$fw" ] && codesign --force --sign - "$fw" 2>/dev/null || true
done
codesign --force --deep --sign - "$APP"
codesign --verify --strict --verbose=1 "$APP" 2>&1 | head -5 || true

echo "=== [6/6] 打 ipa ==="
cd "$WS/Payload"
rm -f "$WS/微颜-vipbypass-signed.ipa"
zip -qrX "$WS/微颜-vipbypass-signed.ipa" .
cd "$WS"
ls -lh "$WS/微颜-vipbypass-signed.ipa"
