#!/usr/bin/env python3
"""nano_flasher.py -- native macOS flashing GUI for the Avalon Nano3s.

A real AppKit window (PyObjC, no web stack): pops up when a Nano3s in burn
mode is plugged in, parses the chosen .kdimg (partitions + verification),
flashes it over USB with a live progress bar and scrolling log, and reboots
the device into mujina when done.

Themed to match the device's Vegas-gold-on-black live UI.

Usage:
    python3 tools/nano_flasher.py            # GUI
    python3 tools/nano_flasher.py --smoke    # build UI + self-test, no run loop
    python3 tools/nano_flasher.py IMAGE.kdimg

Requires: the k230-flash virtualenv (k230_flash, pyusb, loguru) plus
pyobjc-framework-Cocoa. Launch through tools/nano_flasher.command.
"""

import os
import queue
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import k230_flash  # noqa: F401  (verifies the venv up front)
from k230_flash.api import find_devices, flash_kdimg
from loguru import logger

import AppKit
import Foundation
import objc

# ---------------------------------------------------------------- theme ----
BLACK = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.04, 0.04, 0.05, 1.0)
PANEL = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.09, 0.09, 0.11, 1.0)
GOLD = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.83, 0.69, 0.22, 1.0)
GOLD_BRIGHT = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(1.0, 0.84, 0.0, 1.0)
DIM = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.62, 0.60, 0.55, 1.0)
WHITE = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.92, 0.92, 0.90, 1.0)
GREEN = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.30, 0.85, 0.45, 1.0)
RED = AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.95, 0.35, 0.35, 1.0)

GOLD_HEX = "#D4AF37"
BURN_VID, BURN_PID = 0x29F1, 0x0230
POLL_SECONDS = 0.8

# Module-level strong refs for run-loop-owned objects (timer target etc.).
_LIVE = {}

# Default image search order when none is given on the command line.
IMAGE_SEARCH_DIRS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path("/tmp"),
    REPO_ROOT,
]


def find_default_image():
    env = os.environ.get("NANO3S_KDIMG")
    if env and Path(env).is_file():
        return Path(env)
    candidates = []
    for d in IMAGE_SEARCH_DIRS:
        if not d.is_dir():
            continue
        candidates += list(d.glob("*.kdimg"))
        candidates += list(d.glob("nano-mujina*/*.kdimg"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def human_mb(n):
    return f"{n / (1024 * 1024):.1f} MB"


# ------------------------------------------------------------- app state ----
STATE_IDLE = "idle"          # no device
STATE_READY = "ready"        # device detected
STATE_FLASHING = "flashing"
STATE_DONE = "done"
STATE_ERROR = "error"


class FlasherController(Foundation.NSObject):
    """Owns the window, the USB poll timer and the flash worker thread."""

    def initWithImage_(self, image_path):
        self = objc.super(FlasherController, self).init()
        if self is None:
            return None
        self.state = STATE_IDLE
        self.image_path = image_path
        self.image_info = None
        self.q = queue.Queue()
        self.flash_thread = None
        self.flash_error = None
        self.flash_t0 = 0.0
        self.last_progress = (0, 1)
        return self

    # ------------------------------------------------------- UI assembly --
    def build_ui(self):
        frame = Foundation.NSMakeRect(0, 0, 460, 640)
        style = (
            AppKit.NSWindowStyleMaskTitled
            | AppKit.NSWindowStyleMaskClosable
            | AppKit.NSWindowStyleMaskMiniaturizable
        )
        win = AppKit.NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            frame, style, AppKit.NSBackingStoreBuffered, False
        )
        win.setTitle_("Nano3s Flasher")
        win.setBackgroundColor_(BLACK)
        win.setTitlebarAppearsTransparent_(True)
        win.setReleasedWhenClosed_(False)
        self.win = win
        win.setDelegate_(self)

        cv = win.contentView()
        cv.setWantsLayer_(True)
        cv.layer().setBackgroundColor_(BLACK.CGColor())

        def label(text, size, color, bold=False, mono=False, align=None):
            f = AppKit.NSFont.monospacedSystemFontOfSize_weight_(
                size, AppKit.NSFontWeightBold if bold else AppKit.NSFontWeightRegular
            ) if mono else AppKit.NSFont.boldSystemFontOfSize_(size) if bold else (
                AppKit.NSFont.systemFontOfSize_(size)
            )
            par = AppKit.NSMutableParagraphStyle.alloc().init()
            if align is not None:
                par.setAlignment_(align)
            attr = AppKit.NSMutableDictionary.alloc().initWithCapacity_(2)
            attr.setObject_forKey_(f, AppKit.NSFontAttributeName)
            attr.setObject_forKey_(color, AppKit.NSForegroundColorAttributeName)
            attr.setObject_forKey_(par, AppKit.NSParagraphStyleAttributeName)
            tv = AppKit.NSTextField.labelWithString_(text)
            tv.setSelectable_(False)
            tv.setAttributedStringValue_(AppKit.NSAttributedString.alloc().initWithString_attributes_(text, attr))
            return tv

        W, x0 = 460, 24

        title = label("◆ NANO 3S  FLASHER", 22, GOLD, bold=True, mono=True,
                      align=AppKit.NSTextAlignmentCenter)
        title.setFrame_(Foundation.NSMakeRect(x0, 578, W - 2 * x0, 30))
        cv.addSubview_(title)

        sub = label("Avalon Nano3s · mujina custom firmware", 11, DIM,
                    align=AppKit.NSTextAlignmentCenter)
        sub.setFrame_(Foundation.NSMakeRect(x0, 560, W - 2 * x0, 16))
        cv.addSubview_(sub)

        # --- image card (itself the drag-and-drop target; the Choose
        # button stays clickable because hit-testing finds the deepest
        # subview first, and drags over the rest hit the card) ----------
        card = DropView.alloc().initWithFrame_(Foundation.NSMakeRect(x0, 428, W - 2 * x0, 118))
        card.controller = self
        card.setWantsLayer_(True)
        card.layer().setBackgroundColor_(PANEL.CGColor())
        card.layer().setCornerRadius_(10.0)
        cv.addSubview_(card)
        self.image_card = card

        ih = label("IMAGE", 10, DIM, bold=True, mono=True)
        ih.setFrame_(Foundation.NSMakeRect(14, 94, 200, 14))
        card.addSubview_(ih)

        self.image_name = label("—", 12, WHITE, mono=True)
        self.image_name.setFrame_(Foundation.NSMakeRect(14, 64, 320, 20))
        card.addSubview_(self.image_name)
        self.image_name.setLineBreakMode_(AppKit.NSLineBreakByTruncatingMiddle)

        self.image_info = label("", 10, DIM, mono=True)
        self.image_info.setFrame_(Foundation.NSMakeRect(14, 44, 360, 16))
        card.addSubview_(self.image_info)

        choose = AppKit.NSButton.alloc().initWithFrame_(Foundation.NSMakeRect(340, 38, 96, 28))
        choose.setTitle_("Choose…")
        choose.setBezelStyle_(AppKit.NSBezelStyleRounded)
        choose.setTarget_(self)
        choose.setAction_("chooseImage:")
        card.addSubview_(choose)

        hint = label("drop a .kdimg here — or grab the newest from Downloads",
                     9, DIM)
        hint.setFrame_(Foundation.NSMakeRect(14, 10, 330, 14))
        card.addSubview_(hint)

        # --- device status ---------------------------------------------------
        self.dot = label("●", 13, DIM, bold=True)
        self.dot.setFrame_(Foundation.NSMakeRect(x0, 392, 18, 20))
        cv.addSubview_(self.dot)

        self.device_label = label("Looking for a Nano3s in burn mode…", 12, DIM, mono=True)
        self.device_label.setFrame_(Foundation.NSMakeRect(46, 392, W - 46 - x0, 20))
        cv.addSubview_(self.device_label)

        self.burn_hint = label(
            "burn mode: hold the recessed button while powering the device on",
            9, DIM)
        self.burn_hint.setFrame_(Foundation.NSMakeRect(46, 374, W - 46 - x0, 14))
        cv.addSubview_(self.burn_hint)

        # --- progress --------------------------------------------------------
        self.progress = AppKit.NSProgressIndicator.alloc().initWithFrame_(
            Foundation.NSMakeRect(x0, 336, W - 2 * x0, 18))
        self.progress.setIndeterminate_(False)
        self.progress.setMinValue_(0.0)
        self.progress.setMaxValue_(1.0)
        self.progress.setHidden_(True)
        cv.addSubview_(self.progress)

        self.progress_label = label("", 11, GOLD_BRIGHT, mono=True)
        self.progress_label.setFrame_(Foundation.NSMakeRect(x0, 314, W - 2 * x0, 16))
        self.progress_label.setHidden_(True)
        cv.addSubview_(self.progress_label)

        # --- flash button ------------------------------------------------------
        self.flash_btn = AppKit.NSButton.alloc().initWithFrame_(
            Foundation.NSMakeRect(x0, 262, W - 2 * x0, 42))
        self.flash_btn.setTitle_("⚡  FLASH DEVICE")
        self.flash_btn.setBezelStyle_(AppKit.NSBezelStyleRounded)
        self.flash_btn.setTarget_(self)
        self.flash_btn.setAction_("startFlash:")
        self.flash_btn.setEnabled_(False)
        f = AppKit.NSFont.monospacedSystemFontOfSize_weight_(15, AppKit.NSFontWeightBold)
        attr = AppKit.NSMutableDictionary.alloc().initWithCapacity_(2)
        attr.setObject_forKey_(f, AppKit.NSFontAttributeName)
        attr.setObject_forKey_(GOLD_BRIGHT, AppKit.NSForegroundColorAttributeName)
        self.flash_btn.setAttributedTitle_(
            AppKit.NSAttributedString.alloc().initWithString_attributes_("⚡  FLASH DEVICE", attr))
        cv.addSubview_(self.flash_btn)

        # --- log ---------------------------------------------------------------
        logbox = AppKit.NSScrollView.alloc().initWithFrame_(
            Foundation.NSMakeRect(x0, 20, W - 2 * x0, 226))
        logbox.setHasVerticalScroller_(True)
        logbox.setBorderType_(AppKit.NSBezelBorder)
        tv = AppKit.NSTextView.alloc().initWithFrame_(Foundation.NSMakeRect(0, 0, 380, 200))
        tv.setEditable_(False)
        tv.setRichText_(False)
        tv.setBackgroundColor_(AppKit.NSColor.colorWithCalibratedRed_green_blue_alpha_(0.02, 0.02, 0.03, 1.0))
        tv.setTextColor_(DIM)
        tv.setFont_(AppKit.NSFont.monospacedSystemFontOfSize_weight_(10, AppKit.NSFontWeightRegular))
        tv.setAutomaticQuoteSubstitutionEnabled_(False)
        tv.setAutomaticDashSubstitutionEnabled_(False)
        self.log_view = tv
        logbox.setDocumentView_(tv)
        cv.addSubview_(logbox)

        lh = label("LOG", 10, DIM, bold=True, mono=True)
        lh.setFrame_(Foundation.NSMakeRect(x0, 250, 100, 14))
        cv.addSubview_(lh)
        self.log_hint = lh

        self.set_image(self.image_path or find_default_image())
        self.apply_state()

        win.center()
        win.makeKeyAndOrderFront_(None)

    # --------------------------------------------------------- helpers ----
    def log_line(self, line):
        tv = self.log_view
        tv.textStorage().appendAttributedString_(
            AppKit.NSAttributedString.alloc().initWithString_(line.rstrip("\n") + "\n"))
        rng = Foundation.NSMakeRange(tv.string().length(), 0)
        tv.scrollRangeToVisible_(rng)

    def set_image(self, path):
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        from kdimg import KdimgError, load, verify

        self.image_path = Path(path) if path else None
        self.image_info_val = None
        if not self.image_path:
            self.image_name.setStringValue_("no .kdimg found")
            self.image_info.setStringValue_("choose one or drop it above")
            self.apply_state()
            return
        try:
            hdr, parts = load(self.image_path)
            results = verify(self.image_path, parts)
            ok = sum(1 for _, good in results if good)
            self.image_info_val = {
                "name": hdr.get("image_info", ""),
                "board": hdr.get("board_info", ""),
                "parts": [(p.name, p.content_size, p.write_size) for p in parts],
            }
            total = sum(p.write_size for p in parts)
            self.image_name.setStringValue_(self.image_path.name)
            self.image_info.setStringValue_(
                f"{human_mb(self.image_path.stat().st_size)} · {len(parts)} partitions · "
                f"writes {human_mb(total)} · sha256 {ok}/{len(parts)} OK"
            )
            self.image_info.setTextColor_(GREEN if ok == len(parts) else RED)
            self.log_line(f"image: {self.image_path.name} — {len(parts)} partitions, {ok}/{len(parts)} verified")
        except (KdimgError, OSError, ValueError) as e:
            self.image_name.setStringValue_(self.image_path.name)
            self.image_info.setStringValue_(f"unreadable: {e}")
            self.image_info.setTextColor_(RED)
            self.image_info_val = None
            self.log_line(f"image error: {e}")
        self.apply_state()

    def apply_state(self):
        st = self.state
        device_ready = st == STATE_READY
        busy = st == STATE_FLASHING

        if st == STATE_IDLE:
            self.dot.setTextColor_(DIM)
            self.device_label.setStringValue_("Looking for a Nano3s in burn mode…")
            self.device_label.setTextColor_(DIM)
        elif st == STATE_READY:
            self.dot.setTextColor_(GOLD_BRIGHT)
            self.device_label.setStringValue_("Nano3s detected — ready to flash")
            self.device_label.setTextColor_(GOLD_BRIGHT)
        elif st == STATE_FLASHING:
            self.dot.setTextColor_(GOLD_BRIGHT)
            self.device_label.setStringValue_("Flashing… do not unplug the device")
            self.device_label.setTextColor_(WHITE)
        elif st == STATE_DONE:
            self.dot.setTextColor_(GREEN)
            self.device_label.setStringValue_("✅ Flashed! Device is rebooting into mujina")
            self.device_label.setTextColor_(GREEN)
        elif st == STATE_ERROR:
            self.dot.setTextColor_(RED)
            self.device_label.setStringValue_(f"Flash failed: {self.flash_error}")
            self.device_label.setTextColor_(RED)

        can_flash = device_ready and self.image_path is not None and self.image_info_val
        self.flash_btn.setEnabled_(can_flash or st == STATE_ERROR)
        title = "⚡  FLASH DEVICE" if st != STATE_ERROR else "RETRY"
        f = AppKit.NSFont.monospacedSystemFontOfSize_weight_(15, AppKit.NSFontWeightBold)
        attr = AppKit.NSMutableDictionary.alloc().initWithCapacity_(2)
        attr.setObject_forKey_(f, AppKit.NSFontAttributeName)
        attr.setObject_forKey_(GOLD_BRIGHT, AppKit.NSForegroundColorAttributeName)
        self.flash_btn.setAttributedTitle_(
            AppKit.NSAttributedString.alloc().initWithString_attributes_(title, attr))

        self.progress.setHidden_(not busy)
        self.progress_label.setHidden_(not busy)
        if not busy:
            self.progress.setDoubleValue_(0.0)

    # ---------------------------------------------------------- actions ----
    def chooseImage_(self, sender):
        panel = AppKit.NSOpenPanel.openPanel()
        panel.setCanChooseFiles_(True)
        panel.setCanChooseDirectories_(False)
        panel.setAllowedFileTypes_(["kdimg"])
        panel.setDirectoryURL_(Foundation.NSURL.fileURLWithPath_(str(Path.home() / "Downloads")))
        if panel.runModal() == AppKit.NSModalResponseOK and panel.URLs():
            path = panel.URLs()[0].path()
            self.set_image(path)

    def startFlash_(self, sender):
        if self.state == STATE_FLASHING:
            return
        if not self.image_path or not self.image_info_val:
            self.flash_error = "no readable image selected"
            self.state = STATE_ERROR
            self.apply_state()
            return
        devices = find_devices()
        if not devices:
            self.flash_error = "device vanished before flash started"
            self.state = STATE_ERROR
            self.apply_state()
            return

        port_path = devices[0]["port_path"]
        image = self.image_path
        self.state = STATE_FLASHING
        self.flash_error = None
        self.flash_t0 = time.time()
        self.apply_state()
        self.log_line(f"--- flashing {image.name} to device at {port_path} (SPI_NAND) ---")

        self.flash_thread = threading.Thread(
            target=self.flash_worker, args=(image, port_path), daemon=True)
        self.flash_thread.start()

    def flash_worker(self, image, port_path):
        def progress(cur, total):
            self.q.put(("progress", (cur, total)))

        try:
            flash_kdimg(
                str(image),
                port_path=port_path,
                media_type="SPI_NAND",
                auto_reboot=True,
                progress_callback=progress,
            )
            self.q.put(("done", None))
        except Exception as e:  # noqa: BLE001 -- surface everything to the UI
            self.q.put(("error", str(e)))

    # ---------------------------------------------------------- timers ----
    def pollUsb_(self, timer=None):
        # PyObjC selector naming: camelCase + one trailing underscore maps
        # this to the ObjC selector "pollUsb:" (embedded underscores would
        # each become a colon), which is what the NSTimer below targets.
        if not getattr(self, "_tick_traced", False):
            self._tick_traced = True
            print("[poll_usb] first timer tick", flush=True)
        if self.state == STATE_FLASHING:
            self.drain_queue()
            return

        try:
            devices = find_devices()
        except Exception as e:  # noqa: BLE001
            print(f"[poll_usb] find_devices FAILED: {e!r}", flush=True)
            self.log_line(f"usb poll error: {e}")
            devices = []

        if self.state in (STATE_IDLE, STATE_DONE, STATE_ERROR):
            if devices:
                if self.state != STATE_READY:
                    self.state = STATE_READY
                    self.apply_state()
                    self.log_line(f"device detected on port {devices[0]['port_path']}")
            elif self.state == STATE_READY:
                self.state = STATE_IDLE
                self.apply_state()
                self.log_line("device unplugged")

        self.drain_queue()

    def drain_queue(self):
        while True:
            try:
                kind, payload = self.q.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                cur, total = payload
                self.last_progress = (cur, total)
                frac = cur / total if total else 0.0
                self.progress.setDoubleValue_(frac)
                elapsed = max(time.time() - self.flash_t0, 0.001)
                speed = cur / elapsed / (1024 * 1024)
                self.progress_label.setStringValue_(
                    f"{frac * 100:5.1f}%   {human_mb(cur)} / {human_mb(total)}   {speed:.1f} MB/s"
                )
            elif kind == "log":
                self.log_line(payload)
            elif kind == "done":
                elapsed = time.time() - self.flash_t0
                self.log_line(f"--- flash complete in {elapsed:.1f}s — rebooting device ---")
                self.state = STATE_DONE
                self.apply_state()
            elif kind == "error":
                self.flash_error = (payload or "unknown error")[:200]
                self.log_line(f"ERROR: {self.flash_error}")
                self.state = STATE_ERROR
                self.apply_state()

    # window close -> quit
    def windowWillClose_(self, note):
        AppKit.NSApplication.sharedApplication().terminate_(None)


# -------------------------------------------------------------- drop view ----
class DropView(AppKit.NSView):
    controller = None

    def initWithFrame_(self, frame):
        self = AppKit.NSView.initWithFrame_(self, frame)
        if self:
            self.registerForDraggedTypes_([AppKit.NSPasteboardTypeFileURL])
        return self

    def draggingEntered_(self, sender):
        urls = sender.draggingPasteboard().readObjectsForClasses_options_([Foundation.NSURL], None) or []
        for u in urls:
            if u.pathExtension().lower() == "kdimg":
                return AppKit.NSDragOperationCopy
        return AppKit.NSDragOperationNone

    def performDragOperation_(self, sender):
        urls = sender.draggingPasteboard().readObjectsForClasses_options_([Foundation.NSURL], None) or []
        for u in urls:
            if u.pathExtension().lower() == "kdimg":
                self.controller.set_image(u.path())
                return True
        return False


# ------------------------------------------------------------------ main ----
def main():
    # GUI processes launched via `open` have no terminal, so mirror stderr
    # (Python tracebacks, PyObjC warnings, C-level errors) into a log file
    # from the OS level up.
    log_dir = Path.home() / ".nano3s-flasher"
    log_dir.mkdir(exist_ok=True)
    log_fd = os.open(log_dir / "flasher.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    os.dup2(log_fd, 1)  # stdout (prints) -- `open`-launched apps have no tty
    os.dup2(log_fd, 2)  # stderr (warnings, tracebacks)

    cli_image = None
    args = [a for a in sys.argv[1:]]
    smoke = "--smoke" in args
    args = [a for a in args if a != "--smoke"]
    if args:
        cli_image = Path(args[0])

    app = AppKit.NSApplication.sharedApplication()
    app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyRegular)

    controller = FlasherController.alloc().initWithImage_(cli_image)
    controller.build_ui()
    controller.retain()

    # Route the library's loguru output into the GUI log.
    logger.remove()
    logger.add(lambda m: controller.q.put(("log", str(m))), level="INFO", backtrace=False, diagnose=False)

    # Selector must carry the trailing colon for a 1-arg method, and the
    # controller needs a module-level strong reference alongside the ObjC
    # retain, so nothing can collect the timer target out from under it.
    timer = AppKit.NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(
        POLL_SECONDS, controller, "pollUsb:", None, True)
    AppKit.NSRunLoop.mainRunLoop().addTimer_forMode_(timer, Foundation.NSRunLoopCommonModes)
    _LIVE["controller"] = controller
    _LIVE["timer"] = timer

    app.activateIgnoringOtherApps_(True)

    if smoke or os.environ.get("NANO3S_SMOKE") == "1":
        controller.pollUsb_(None)
        info = controller.image_info_val
        assert info and info["parts"], "image parsing failed"
        assert controller.image_path is not None
        print(f"SMOKE OK: image={controller.image_path.name} parts={len(info['parts'])} "
              f"state={controller.state} devices={len(find_devices())}")
        return 0

    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
