# FLASHING.md — the flash pipeline that actually works

> Field notes from 2026-09-11/12: four images "bricked" one Nano 3s, and every
> stock/fork flashing tool failed in a different way before we found a recipe
> that works every time. This document is that recipe plus the autopsies.
>
> **If you read nothing else: [the recipe](#the-recipe-erase--flash--boot).**

---

## TL;DR — the recipe (erase → flash → boot)

Two tools, both installed once:

| Tool | What it is | Install |
|---|---|---|
| **Canaan's official C++ CLI** (`k230_flash_cli`) | The *only* tool with a working full-chip erase. From `github.com/kendryte/k230_flash` releases (v0.0.11). | download, `chmod +x` |
| **Python `k230-flash`** | The only tool that speaks the `kdimg` container format. | `python3 -m pip install k230-flash` into a venv |

Per flash:

```bash
# 0. Device in burn mode: unplug everything, hold the recessed button,
#    plug in the USB data cable, release after ~2s. Device shows as "20-x.y".

# 1. Full-chip erase with the C++ CLI (global flags BEFORE the subcommand!)
~/.k230-cli/k230_flash_cli*/bin/k230_flash_cli -m SPI_NAND --log-level WARN \
    erase --address 0 --size 0x10000000
#    → "Erase 0x00000000 to 0x10000000 done, use ~5.3 sec" = real work.
#      (A trailing LIBUSB_ERROR_TIMEOUT line is cosmetic; exit code is what counts.)

# 2. Flash the kdimg with the Python tool (it handles the container format)
~/.nano3s-flasher/venv/bin/k230-flash -m SPI_NAND path/to/image.kdimg
#    → every partition 100.00%, "固件写入完成" (write complete)

# 3. Boot test: unplug everything → PSU only → wait 2–3 min.
```

**Erase first, every time.** It costs 5 seconds and removes the entire class of
layout-corruption failures described below.

---

## The war story (why this document exists)

Starting state: an Avalon Nano 3s that hung at the stock boot logo on *every*
image — stock firmware from Canaan, the fork's release image, our custom
builds, reflashed multiple times, on both the Python CLI and the GUI app.

| What we tried | Result |
|---|---|
| Fork image, Python CLI flash | ❌ hangs at logo |
| Stock Canaan image, Python CLI flash | ❌ hangs at logo |
| Fork image, official GUI app | ❌ hangs at logo |
| Fork image, GUI app with DEBUG logging | ❌ hangs at logo — but logs proved the flash itself completed 100% |

**The flash was never the problem. The flash *succeeded every time*.**
The question was what it was succeeding *onto*.

### Root cause #1 — NAND layout corruption (the "bricked" device)

Earlier that night, two flash runs had been interrupted mid-write (both died
around 41% of `rootfs_ubi`, ≈ offset `0x02400000`). A NAND write that dies
mid-block leaves that block in an indeterminate state; subsequent writes skip
or misplace data relative to what the boot ROM expects. Every image flashed
after that — *any* image, stock included — landed on a corrupted layout and
hung identically at the logo.

**Fix: full-chip erase.** Which is where the next problem appeared.

### Root cause #2 — the Python tool cannot erase

The Python `k230-flash` (and the GUI app built on it) ships a USB loader that
implements only: probe, get-info, write, reboot. We proved this by sending
`READ_LBA` and `ERASE_LBA` commands directly — the device answered `0x8000`
("unknown command") to both. That's also why the stock tool "silently copes"
with bad blocks: it *can't* erase, so it can only skip — which is exactly the
behavior that corrupts layouts after an interrupted write.

**Fix:** Canaan's C++ CLI (`kendryte/k230_flash`, releases) — its source
implements `kburn_erase()` with retries, and it ships a *newer loader build*
(different SHA256 and size) that actually implements erase on-device. Verified:
full-chip erase ran 2048 blocks in 5.27s of real work. One full erase later,
**stock firmware booted on the first try** — the "bricked" device was never
bricked.

> Note: the C++ CLI's `erase` subcommand wants global flags (`-m SPI_NAND`)
> *before* the subcommand. After them, the parser rejects it.
> Its `read` subcommand has a protocol quirk in v0.0.11 (expects a 32 KB data
> chunk, gets the 60-byte status packet first). Don't rely on it; see
> `tools/nand_readback.py` instead.

### Root cause #3 — UBIFS rebuild dropped execute bits (the WiFi killer)

After custom images started booting, WiFi provisioning failed with: empty scan
list in the Avalon Family app, then every credential save reporting "failed."
The fork's *proven* release image (`nano-mujina-alpha-v2.kdimg`) worked — so we
diffed file-by-file against it.

Content matched byte-for-byte. **Permissions didn't.**

| File | alpha-v2 (proven) | our rebuild |
|---|---|---|
| `wifi_bringup.sh` | `rwxr-x---` (750) | `rw-r--r--` (644) |
| `fb_button`, `mujina_test_harness`, all bringup scripts | 750 | 644 |

`rcS` launches these by direct execution — which fails with *Permission denied*
even for root when no x-bit is set, and `rcS`'s `2>/dev/null` swallows the
error. So `wpa_supplicant` **never started**; the scan list was empty because
`wpa_cli` had nothing to talk to. The UBIFS extract→rebuild step
(`ubireader_extract_files` + `mkfs.ubifs`) loses the mode bits of every
base-image file; only files staged fresh through the overlay kept their `+x`.

**Fix:** `tools/ubifs_rebuild.sh` now restores the proven image's conventions
after extraction: 750 on everything under `app_ubi` (startup script 755),
755 on the `data` volume.

### Root cause #4 — startup-script ordering (logo never showed)

`mujina_display_startup.sh` wrote the `bootlogo` page to the framebuffer page
file and held 5 seconds — but `nano3s_ui`, the only process that *reads* the
page file and draws, wasn't launched until a minute later. Nothing rendered
the logo. The fork's own live script had the same latent ordering for BLE:
`ble_setup` was on the data volume but never launched, so the device never
advertised and the app couldn't see it.

**Fix:** launch the UI renderer **first**, then the BLE loop
(`hciconfig hci0 down` before every `ble_setup` start — mirrors the proven
image; `ble_setup` claims `HCI_CHANNEL_USER`, which needs hci0 clean), then put
the bootlogo page up, then switch to the live page.

### Root cause #5 — `--fresh-data` wiped the WiFi config home

The fresh-data wipe removed `/data/userconfig/` entirely. But
`wifi_bringup.sh` starts `wpa_supplicant` with
`-c /data/userconfig/wpa_supplicant.conf`, and with no config file the daemon
exits immediately — even with perfect exec bits. Empty seed config fixed the
scan; baking real credentials fixed provisioning altogether.

**Fix:** the build seeds `/data/userconfig/wpa_supplicant.conf` after the wipe.
Pass `WIFI_SSID` (+ optional `WIFI_PASS`) as environment variables and the
config is baked in `ble_setup`'s exact format — the device auto-joins WiFi at
first boot with no app involved. This is what made v5 join the network before
anyone touched it.

---

## Building a custom image

```bash
# inputs (all optional — anything omitted keeps the base image's version):
#   rtos_core/build/rtos_core.elf          big-core RTOS
#   mujina-miner/target/.../mujina-minerd.stripped   miner (static, /data)
#   nano3s_ui/target/.../nano3s_ui         LVGL UI (static, /data)
#   tools/bootlogo.rgb565                  240x240 RGB565 boot logo
#                                          (tools/make_bootlogo.py generates it)

export WIFI_SSID="YourSSID"      # optional: bake WiFi creds into the image
export WIFI_PASS="YourPassword"  # omit for an open network
export PATH="$HOME/.docker/bin:$PATH"   # needs Docker (the UBIFS step is Linux-only)

tools/build_kdimg.sh \
    --base  ~/Downloads/nano-mujina-alpha-v2.kdimg \
    --out   ~/Downloads/nano-mujina-custom.kdimg \
    --pool  "stratum+tcp://pool.example.org:3333" \
    --user  "WALLET.worker" \
    --fresh-data
```

What `--fresh-data` does: strips old WiFi credentials/logs so the device boots
into first-time provisioning state — then seeds `userconfig/` (with your baked
credentials if provided). Never touches `/data/factory` (calibration).

**Always verify the built image before flashing** (the whole point of this doc
is that a flash can succeed while being wrong):

```bash
python3 tools/kdimg.py verify image.kdimg          # → "N/N partitions verified"
python3 tools/kdimg.py extract image.kdimg /tmp/ic # then inspect payloads

# inspect the UBIFS volumes (macOS-friendly, zlib-compressed images):
#   ubidump.py = pure-python UBIFS reader (pip install ubi-reader, or grab
#   ubidump.py standalone) + a stub lzo.py next to it containing:
#       def decompress(data, *a): raise NotImplementedError
#   (our volumes are zlib-compressed, so the lzo stub is never called)
python3 /tmp/ubidump.py -l   /tmp/ic/parts/app_ubi.bin   # list + perms
python3 /tmp/ubidump.py --cat release/linux/app/mujina_display_startup.sh \
                             /tmp/ic/parts/app_ubi.bin   # check pool/logo order
python3 /tmp/ubidump.py --cat userconfig/wpa_supplicant.conf \
                             /tmp/ic/parts/data.bin      # check baked creds
```

Checklist against the proven image:
- [ ] `wifi_bringup.sh` (and every app script) shows `rwxr-x---`
- [ ] startup script: `nano3s_ui` launched **before** `echo bootlogo > fb_page`
- [ ] BLE loop present, `hciconfig hci0 down` before `ble_setup`
- [ ] `userconfig/wpa_supplicant.conf` present with the right content
- [ ] factory calibration intact on the data volume

---

## The recipe (erase → flash → boot)

Full version, including recovery:

```bash
# — setup, once —
# Python tool + venv:
python3 -m venv ~/.nano3s-flasher/venv
~/.nano3s-flasher/venv/bin/pip install k230-flash
# C++ CLI (real erase support):
#   grab k230_flash_cli-macos-x86_64-*.zip from kendryte/k230_flash releases
mkdir -p ~/.k230-cli && cd ~/.k230-cli && unzip ~/Downloads/k230_flash_cli-*.zip
chmod +x ~/.k230-cli/*/bin/k230_flash_cli

# — per flash —
CPP=$(find ~/.k230-cli -name k230_flash_cli -type f | head -1)

# 1. device in burn mode (unplug → hold button → plug USB data cable → release ~2s)
# 2. erase:
"$CPP" -m SPI_NAND --log-level WARN erase --address 0 --size 0x10000000
# 3. flash:
LOG=/tmp/k230_flash.log
~/.nano3s-flasher/venv/bin/k230-flash -m SPI_NAND image.kdimg 2>&1 | tee "$LOG" \
    | grep -E "固件写入完成|ERROR|失败"
grep -c "100.00%" "$LOG"   # must equal the partition count (11 on Nano 3s)
# 4. unplug everything → PSU only → wait 2–3 min
```

### GUI app (`nano_flasher`)

`tools/nano_flasher.py` (and `nano_flasher.command` to launch it) is a local
GUI wrapper around the same Python tool. Useful for quick single-image flashes
**after** an erase. Remember its bundled loader can't erase — do the erase with
the C++ CLI first, then flash from the GUI.

### Boot behavior to expect (custom image, verified working)

1. stock Avalon splash, ~30–60 s (normal)
2. custom boot logo, ~8 s
3. live 12-ASIC Vegas UI — grid + stats fit inside the round panel
4. if WiFi creds are baked in: wlan0 associates + DHCP in the background,
   miner connects to the pool within ~a minute (60 s wait loop in the startup
   script); if not: BLE advertises, Avalon Family app provisions

---

## Post-flash verification (no serial console needed)

The image runs an API on port 80 and real sshd on port 22, root with empty
password. Once the device is on the LAN:

```bash
# find it (look for the host with both 80 and 22 open; ssh banner "OpenSSH"):
for i in $(seq 1 254); do (ping -c1 -W800 192.168.0.$i >/dev/null 2>&1 &); done
sleep 6; arp -a | grep "192.168.0."

curl http://<ip>/data   # JSON: hashrate, per-chip temps, fan, power, pool
ssh root@<ip>           # full shell; logs at /data/mujina-minerd.log, /sharefs/*.log
```

Healthy boot, from `/data/mujina-minerd.log`:

```
INFO  job_source::stratum_v1: Subscribed.
      pool=stratum+tcp://…, user=WALLET.worker
INFO  job_source::stratum_v1: First share accepted.
```

Useful `…/data` fields: `hashrate_ghs`, `total_power_w`, `fail_rate_pct`
(ASIC-internal SmartSpeed fails — the dashboard alerts at ≥35%; single digits
is healthy; near-100% right after boot just means voltage is still ramping),
`avg_freq_mhz`, `fans[].percent`, per-chip `temp_c`.

---

## Gotchas learned the hard way

1. **A successful flash is not a correct flash.** Verify the *image* (verify +
   volume inspect) and the *boot* (SSH/API), never trust progress bars.
2. **Interrupted flash ⇒ full-chip erase before the next one.** No exceptions.
   The symptoms of layout corruption are identical to a bad image: hang at
   logo, every image, every tool.
3. **The Python tool's GUI/CLI report success while the NAND is sick.** It
   cannot read back or erase. Erase with the C++ CLI; read back with
   `tools/nand_readback.py`.
4. **C++ CLI flag order matters:** `-m SPI_NAND` etc. go *before* the
   subcommand.
5. **Loader wedged?** After failed experiments the USB loader can stop
   answering (probe timeouts in every tool). Only fix: power-cycle the board
   into burn mode again.
6. **UBIFS rebuilds lose exec bits** — any pipeline that extracts + repacks a
   UBIFS volume needs an explicit mode restoration step (see
   `tools/ubifs_rebuild.sh`).
7. **`rcS` swallows script failures** (`2>/dev/null` + direct exec). If WiFi or
   fans are dead on a booting device, check modes and paths *inside the
   actual flashed image*, not the repo.
8. **Device path varies** (`20-6.2`, `20-3`, …). Passing no `--device-path`
   lets the tool pick the single present device.
9. **wlan0 is a USB WiFi dongle** (2.4 GHz). Association needs the dongle's
   driver + wpa_supplicant running; association failures look identical to
   provisioning failures — check `wpa_cli status` over SSH before blaming the
   app or the image.
10. **The Avalon ASICs run hot by design** (per the fork author). Ours cruises
    at mid-80s °C at the 133 W OC target with auto fan. The numbers to watch
    over time: `err_crc` (flat = good), fail rate (single digits), and whether
    temps *trend* upward day over day.

---

## Tool inventory (`tools/`)

| File | Purpose |
|---|---|
| `kdimg.py` | unpack/verify/repack Canaan `kdimg` containers |
| `build_kdimg.sh` | full custom-image build: extract base → overlay our binaries → rebuild UBIFS volumes → repack (Docker for the Linux-only step) |
| `ubifs_rebuild.sh` | the container-side UBIFS rebuild: extract, overlay, fresh-data wipe + `userconfig` seed (WiFi bake-in), **exec-bit restoration**, vendor-recipe `mkfs.ubifs`/`ubinize` replay |
| `nand_erase.py` | standalone erase attempt via the Python tool (kept for reference — *does not work*: loader lacks `ERASE_LBA`) |
| `nand_readback.py` | NAND read-back verification via raw protocol |
| `nano_flasher.py` / `.command` | local GUI wrapper for single-image flashes |
| `make_bootlogo.py` | generate `bootlogo.rgb565` (240×240 RGB565) |
| `build_all.sh` | build all firmware components end-to-end |

## Stack status (what's running on the device now)

- big-core RTOS (`rtos_core.elf`): ASIC chain control + IPC
- `mujina-minerd`: Stratum v1 miner, 3-mode power system
  (`stock` / `oc` 420 MHz 133 W / `bypass`), persisted in
  `/data/mujina_power_mode`
- `nano3s_ui`: LVGL UI fitted to the round panel (fork's safe-zone geometry)
- `ble_setup`: Avalon Family provisioning, launched supervised
- boot logo, auto fan, API dashboard on :80, sshd on :22
- verified end-to-end: **6.2 TH/s @ 133 W OC, shares accepted at the pool,
  WiFi auto-join at first boot, OC persists across reboots**
