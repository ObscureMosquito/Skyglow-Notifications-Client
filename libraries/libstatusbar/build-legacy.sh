#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$ROOT/src"
LIB_DIR="$ROOT/lib"
BUILD_DIR="$ROOT/.build"
PKG_DIR="$BUILD_DIR/pkg"
mkdir -p "$BUILD_DIR"

SDK_PATH_2_0="$HOME/theos/sdks/iPhoneOS2.0.sdk"
SDK_PATH_4_3="$HOME/theos/sdks/iPhoneOS4.3.sdk"
SDK_PATH_6_0="$HOME/theos/sdks/iPhoneOS6.0.sdk"
SDK_PATH_7_0="$HOME/theos/sdks/iPhoneOS7.0.sdk"

SRC_FILES=(
    libstatusbar.mm
    Classes.mm
    LSStatusBarClient.mm
    LSStatusBarServer.mm
    UIStatusBarCustomItem.mm
    UIStatusBarCustomItemView.mm
    LSStatusBarItem.mm
)

COMMON_INCLUDES=(
    -I"$SRC_DIR"
    -I"$HOME/theos/vendor/include"
    -I"$HOME/theos/vendor/include/AppSupport"
    -I"$HOME/theos/include"
)

COMMON_CFLAGS=(
    -fobjc-abi-version=2
    -fobjc-legacy-dispatch
    -fno-objc-arc
    -fvisibility=hidden
    -DGO_EASY_ON_ME=1
    -include "$SRC_DIR/sgn_shims.h"
    -w
    -include dlfcn.h
)

compile_arch() {
    local arch="$1" sdk="$2" min="$3" out_dylib="$4"
    echo "  cc [$arch min=$min sdk=$(basename "$sdk")]"
    local objs=()
    for f in "${SRC_FILES[@]}"; do
        local src="$SRC_DIR/$f"
        local obj="$BUILD_DIR/${f%.mm}.${arch}.o"
        xcrun --sdk "$sdk" clang++ \
            -arch "$arch" -miphoneos-version-min="$min" \
            "${COMMON_INCLUDES[@]}" "${COMMON_CFLAGS[@]}" \
            -isysroot "$sdk" \
            -c "$src" -o "$obj"
        objs+=("$obj")
    done
    local extra=()
    if [ "$arch" != "arm64" ] && [ -f "$sdk/usr/lib/dylib1.o" ]; then
        extra+=("$sdk/usr/lib/dylib1.o")
    fi
    xcrun --sdk "$sdk" ld -arch "$arch" -ios_version_min "$min" -dylib \
        -syslibroot "$sdk" \
        -L"$sdk/usr/lib" \
        -F"$sdk/System/Library/PrivateFrameworks" \
        -F"$HOME/theos/vendor/lib" \
        -framework Foundation -framework UIKit \
        -framework AppSupport -framework SpringBoardServices \
        -framework CydiaSubstrate \
        -lobjc -lc -lsandbox \
        "${extra[@]}" \
        "${objs[@]}" \
        -install_name /Library/MobileSubstrate/DynamicLibraries/libstatusbar.dylib \
        -o "$out_dylib"
}

echo "Building libstatusbar:"
compile_arch armv6  "$SDK_PATH_4_3" 4.0 "$BUILD_DIR/libstatusbar.armv6.dylib"
compile_arch armv7  "$SDK_PATH_4_3" 4.0 "$BUILD_DIR/libstatusbar.armv7.dylib"
compile_arch armv7s "$SDK_PATH_6_0" 6.0 "$BUILD_DIR/libstatusbar.armv7s.dylib"
compile_arch arm64  "$SDK_PATH_7_0" 7.0 "$BUILD_DIR/libstatusbar.arm64.dylib"

echo "Fusing fat dylib:"
lipo -create -output "$BUILD_DIR/libstatusbar.dylib" \
    "$BUILD_DIR/libstatusbar.armv6.dylib" \
    "$BUILD_DIR/libstatusbar.armv7.dylib" \
    "$BUILD_DIR/libstatusbar.armv7s.dylib" \
    "$BUILD_DIR/libstatusbar.arm64.dylib"

echo "  $(lipo -info "$BUILD_DIR/libstatusbar.dylib")"

echo "Packaging .deb:"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/Library/MobileSubstrate/DynamicLibraries"
mkdir -p "$PKG_DIR/usr/include/libstatusbar"

cp "$SRC_DIR/control"                "$PKG_DIR/DEBIAN/control"
cp "$BUILD_DIR/libstatusbar.dylib"   "$PKG_DIR/Library/MobileSubstrate/DynamicLibraries/"
cp "$SRC_DIR/libstatusbar.plist"     "$PKG_DIR/Library/MobileSubstrate/DynamicLibraries/"

for h in CPDistributedMessagingCenter.h LSStatusBarClient.h LSStatusBarItem.h \
         LSStatusBarServer.h UIApplication_libstatusbar.h \
         UIStatusBarCustomItem.h UIStatusBarCustomItemView.h \
         classes.h classlist.h common.h defines.h; do
    cp "$SRC_DIR/$h" "$PKG_DIR/usr/include/libstatusbar/"
done

find "$PKG_DIR" -name ".DS_Store" -type f -delete

PKG_ID=$(awk '/^Package:/ {print $2}' "$SRC_DIR/control")
PKG_VER=$(awk '/^Version:/ {print $2}' "$SRC_DIR/control")
OUT_DEB="$ROOT/../../packages/${PKG_ID}_${PKG_VER}_iphoneos-arm.deb"
mkdir -p "$(dirname "$OUT_DEB")"
dpkg-deb -Zgzip --build "$PKG_DIR" "$OUT_DEB"

mkdir -p "$LIB_DIR"
cp "$BUILD_DIR/libstatusbar.dylib" "$LIB_DIR/libstatusbar.dylib"

echo "Done: $OUT_DEB"
echo "      $LIB_DIR/libstatusbar.dylib"
rm -rf "$BUILD_DIR"
