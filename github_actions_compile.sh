#!/bin/bash
# GitHub Actions macOS: 编译 vipbypass.dylib + 完整 inject_dylib.py 注入 + 签名 + 打 ipa
set -euo pipefail
WS="$GITHUB_WORKSPACE"
cd "$WS"

echo "=== [1/6] 拼回原始主二进制 (o000..o014) ==="
ls o0* | sort | xargs -I{} cat {} > WeChat_orig
ls -lh WeChat_orig
echo "size=$(wc -c < WeChat_orig)"

echo "=== [2/6] 解压资源分卷 (r*.tgz, tar 原生 UTF-8 中文文件名) ==="
mkdir -p Payload/WeChat.app
for t in r0*.tgz; do
  [ -s "$t" ] && tar -xzf "$t" -C . || echo "  skip empty $t"
done
[ -f "Payload/WeChat.app/vipbypass_src/vipbypass.m" ] || { echo "缺 vipbypass.m"; exit 1; }
echo "资源解压 OK"

echo "=== [3/6] 编译 vipbypass.dylib (arm64 iOS) ==="
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
cp WeChat_orig "Payload/WeChat.app/WeChat"
clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=12.0 \
  -fobjc-arc -dynamiclib -framework Foundation -framework UIKit -lobjc \
  -Wl,-install_name,@rpath/vipbypass.dylib \
  "Payload/WeChat.app/vipbypass_src/vipbypass.m" -o "Payload/WeChat.app/Frameworks/vipbypass.dylib"
echo "  dylib install name 已设为 @rpath/vipbypass.dylib (匹配 LC_RPATH @executable_path/Frameworks)"
ls -lh "Payload/WeChat.app/Frameworks/vipbypass.dylib"

echo "=== [4/6] 注入主二进制 (完整 inject_dylib.py, __LINKEDIT 同步) + strip 旧签名 ==="
python3 "$WS/inject_dylib.py" "Payload/WeChat.app/WeChat" "Payload/WeChat.app/Frameworks/vipbypass.dylib" "@rpath/vipbypass.dylib"
python3 "$WS/strip_codesig.py" "Payload/WeChat.app/WeChat"

echo "=== [5/6] 签名 ==="
APP="Payload/WeChat.app"
codesign --force --sign - "$APP/Frameworks/vipbypass.dylib"
for fw in "$APP"/Frameworks/*.framework; do
  [ -e "$fw" ] && codesign --force --sign - "$fw" 2>/dev/null || true
done
codesign --force --deep --sign - "$APP"
codesign --verify --strict --verbose=1 "$APP" 2>&1 | head -5 || true

echo "=== [6/6] 打 ipa (zip 根下 Payload/, POSIX 分隔符) ==="
# 在 $WS 下 (含 Payload/ 目录) 打, 条目 = Payload/WeChat.app/...
rm -f "$WS/微颜-vipbypass-signed.ipa"
cd "$WS"
zip -qrX "$WS/微颜-vipbypass-signed.ipa" Payload
ls -lh "$WS/微颜-vipbypass-signed.ipa"
