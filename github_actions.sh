#!/bin/bash
# GitHub Actions macOS 签名 pipeline (修正版: 主二进制分块传)
# 输入: bin_part00..bin_partNN (主二进制 90MB 块) + rest.zip (其余资源) + manifest.txt
# 输出: 微颜-gadget-signed.ipa (签名版, artifact)
set -euo pipefail
WS="$GITHUB_WORKSPACE"

echo "=== 拼回主二进制 ==="
cd "$WS"
# manifest.txt 列出分块顺序
ls bin_part* | sort > /tmp/order.txt
cat $(cat /tmp/order.txt) > WeChat_patched
# WeChat_patched 就是注入+strip 后的主二进制 (YG 本机已处理好)
ls -lh WeChat_patched

echo "=== 解压资源 (rest.zip 含 Payload/WeChat.app 除主二进制外全部) ==="
unzip -q rest.zip
APP="Payload/WeChat.app"
[ -d "$APP" ] || { echo "rest.zip 解压失败"; exit 1; }

echo "=== 把拼好的主二进制放回 app ==="
cp WeChat_patched "$APP/WeChat"
chmod +x "$APP/WeChat"

echo "=== 签名 frida-gadget.dylib + frameworks ==="
codesign --force --sign - "$APP/Frameworks/frida-gadget.dylib"
for fw in "$APP"/Frameworks/*.framework; do
  [ -e "$fw" ] && codesign --force --sign - "$fw" 2>/dev/null || true
done

echo "=== 签主 app (deep) ==="
codesign --force --deep --sign - "$APP"
echo "verify:"
codesign --verify --strict --verbose=1 "$APP" 2>&1 | head -10 || true

echo "=== 打 ipa (zip, POSIX / 分隔符) ==="
rm -f "$WS/微颜-gadget-signed.ipa"
zip -qrX "$WS/微颜-gadget-signed.ipa" Payload
ls -lh "$WS/微颜-gadget-signed.ipa"
