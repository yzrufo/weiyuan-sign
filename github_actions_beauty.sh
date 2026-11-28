#!/bin/bash
# 一键编译 + 注入 + 签名 + 打包
# 输入: WeChat_8079_bea u tified/ (已解压的微信 IPA，含微颜 bundle)
set -euo pipefail
WS="$GITHUB_WORKSPACE"
APP="$WS/WeChat_8079_beautified/Payload/WeChat.app"
BIN="$APP/WeChat"

echo "=== [1/5] 编译 wechat_beauty_loader.dylib ==="
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=12.0 \
  -fobjc-arc -dynamiclib -framework Foundation \
  -Wl,-install_name,@executable_path/Frameworks/wechat_beauty_loader.dylib \
  "$WS/wechat_beauty_loader.m" -o "$APP/Frameworks/wechat_beauty_loader.dylib"
chmod +x "$APP/Frameworks/wechat_beauty_loader.dylib"
ls -lh "$APP/Frameworks/wechat_beauty_loader.dylib"

echo "=== [2/5] 注入主二进制 ==="
python3 "$WS/inject_beauty.py" "$BIN" "$APP/Frameworks/wechat_beauty_loader.dylib"
echo "注入完成"

echo "=== [3/5] strip 旧签名 ==="
python3 "$WS/../gadget/strip_codesig.py" "$BIN" 2>/dev/null || true

echo "=== [4/5] 签名所有 dylib + framework + app ==="
codesign --force --sign - "$APP/Frameworks/wechat_beauty_loader.dylib"
for fw in "$APP"/Frameworks/*.framework; do
  [ -e "$fw" ] && codesign --force --sign - "$fw" 2>/dev/null || true
done
for bndl in "$APP"/Frameworks/*.bundle; do
  [ -e "$bndl" ] && codesign --force --sign - "$bndl" 2>/dev/null || true
done
codesign --force --deep --sign - "$APP"
echo "签名完成"
codesign --verify --strict "$APP" 2>&1 | head -3 || true

echo "=== [5/5] 打 ipa ==="
cd "$WS/WeChat_8079_beautified"
rm -f "$WS/WeChat_8079_beautified_signed.ipa"
zip -qrX "$WS/WeChat_8079_beautified_signed.ipa" Payload
ls -lh "$WS/WeChat_8079_beautified_signed.ipa"
echo "=== 完成: $WS/WeChat_8079_beautified_signed.ipa ==="
