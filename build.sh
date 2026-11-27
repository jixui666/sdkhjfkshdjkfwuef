#!/usr/bin/env bash
# 多载荷构建：./build.sh <载荷名>
#
#   ./build.sh photonote     → out/photonote.dylib
#   ./build.sh screenstream  → out/screenstream.dylib（以后加的）
#
# 每个载荷目录里的 *.m 会和 common/*.m 一起编译。
set -euo pipefail

cd "$(dirname "$0")"
TARGET="${1:-photonote}"

if [ ! -d "$TARGET" ]; then
  echo "没有这个载荷目录: $TARGET"
  echo "现有: $(ls -d */ 2>/dev/null | grep -v -E '^(tools|common|out)/' | tr -d '/' | tr '\n' ' ')"
  exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p out

SOURCES=("${TARGET}"/*.m common/*.m)
INCLUDES=(-Icommon -I"$TARGET")

LINK=(
  -framework Foundation -framework UIKit -framework Photos
  -framework CoreGraphics -framework Security
  -lsqlite3
)

COMMON=(
  -miphoneos-version-min=14.0
  -isysroot "$SDK"
  -dynamiclib -fobjc-arc -O2 -fvisibility=hidden
  "${INCLUDES[@]}"
  "${LINK[@]}"
  -install_name @rpath/"${TARGET}".dylib
)

echo "==> $TARGET 源文件: ${SOURCES[*]}"

echo "==> arm64"
xcrun --sdk iphoneos clang -arch arm64 "${COMMON[@]}" -o "out/${TARGET}_arm64.dylib" "${SOURCES[@]}"

echo "==> arm64e"
if xcrun --sdk iphoneos clang -arch arm64e "${COMMON[@]}" -o "out/${TARGET}_arm64e.dylib" "${SOURCES[@]}" 2>/dev/null; then
  lipo -create -output "out/${TARGET}.dylib" "out/${TARGET}_arm64.dylib" "out/${TARGET}_arm64e.dylib"
else
  echo "    arm64e 不支持，只出 arm64"
  cp "out/${TARGET}_arm64.dylib" "out/${TARGET}.dylib"
fi

lipo -info "out/${TARGET}.dylib"
ls -l "out/${TARGET}.dylib"
shasum -a 256 "out/${TARGET}.dylib"
echo
echo "产物: $(pwd)/out/${TARGET}.dylib"
echo "打包: python tools/pack.py out/${TARGET}.dylib ${TARGET} --deploy"
