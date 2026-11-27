#!/usr/bin/env python3
"""把编译好的 dylib 打成服务器要的 .js（7z 容器），并算出 config 需要的 sha256/size。

用法:
    python tools/pack.py <Payload.dylib> [输出名] [--deploy]

    # 例：打成 px1.js，直接写进 delivery-web/public/details/
    python tools/pack.py out/Payload.dylib px1 --deploy

注意:
    服务器 show.html 的 entries 校验的是**解开后的 dylib** 的 sha256 和 size，
    所以这里打印的是 dylib 本身的 hash/大小，不是 .js 的。
"""
import sys, os, io, json, shutil, hashlib
import py7zr

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SEVENZ_PASSWORD = "abf3bdc8e239c0f3183c257f9ccc23e8"   # README 里 new.js / show.html 的 7z 密码
DETAILS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "delivery-web", "public", "details"))


def pack(dylib_path: str, name: str) -> dict:
    raw = open(dylib_path, "rb").read()
    entry = os.path.basename(dylib_path)          # 7z 内部文件名，例如 Payload.dylib
    sha = hashlib.sha256(raw).hexdigest()
    size = len(raw)

    out_js = os.path.join(os.path.dirname(dylib_path), name + ".js")
    if os.path.exists(out_js):
        os.remove(out_js)

    # 写法与服务器 stage2.ts 一致：加密头 + 单个 entry
    with py7zr.SevenZipFile(out_js, "w", password=SEVENZ_PASSWORD, header_encryption=True) as z:
        z.write(dylib_path, entry)

    # 自校验：解回来要和原文件一模一样
    tmp = os.path.join(os.path.dirname(out_js), "_verify")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
    with py7zr.SevenZipFile(out_js, "r", password=SEVENZ_PASSWORD) as z:
        names = z.getnames()
        z.extractall(path=tmp)
    back = open(os.path.join(tmp, os.path.basename(names[0])), "rb").read()
    ok = hashlib.sha256(back).hexdigest() == sha
    shutil.rmtree(tmp, ignore_errors=True)

    return {
        "name": name,
        "entry": entry,
        "js": out_js,
        "js_size": os.path.getsize(out_js),
        "sha256": sha,
        "size": size,
        "verified": ok,
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    deploy = "--deploy" in sys.argv

    if not args:
        print(__doc__)
        sys.exit(2)

    dylib = args[0]
    if not os.path.isfile(dylib):
        print("找不到:", dylib)
        sys.exit(1)

    name = args[1] if len(args) > 1 else "px1"

    r = pack(dylib, name)
    print("=" * 56)
    print("  7z 容器 : %s  (%d B)" % (os.path.basename(r["js"]), r["js_size"]))
    print("  内部文件 : %s" % r["entry"])
    print("  dylib    : %d B" % r["size"])
    print("  sha256   : %s" % r["sha256"])
    print("  自校验   : %s" % ("✓ 解回来一致" if r["verified"] else "✗ 不一致！"))
    print("=" * 56)
    print()
    print("把下面这段填进 show.html 对应 bundleId 的 entry：")
    print(json.dumps({
        "url": "http://[HOST_PLACEHOLDER]/details/%s.js" % name,
        "sha256": r["sha256"],
        "size": r["size"],
    }, indent=2, ensure_ascii=False))

    if deploy:
        os.makedirs(DETAILS_DIR, exist_ok=True)
        dst = os.path.join(DETAILS_DIR, name + ".js")
        shutil.copy2(r["js"], dst)
        print("\n已部署 -> %s (%d B)" % (dst, os.path.getsize(dst)))


if __name__ == "__main__":
    main()
