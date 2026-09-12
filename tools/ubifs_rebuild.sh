#!/bin/bash
# ubifs_rebuild.sh -- rebuild the app_ubi and data UBI volumes with this
# repo's overlay applied. Runs INSIDE a Linux container (invoked by
# build_kdimg.sh); needs mtd-utils (mkfs.ubifs/ubinize), which is why it
# is the pipeline's single non-macOS step.
#
# Usage (from inside a container with mtd-utils + python3):
#   bash ubifs_rebuild.sh /work
#
# /work is build_kdimg.sh's work directory, expected to contain:
#   parts/app_ubi.bin, parts/data.bin   -- base image's raw volume payloads
#   overlay/app_ubi/...                 -- files copied over the extracted trees
#   overlay/data/...
#
# Produces:
#   parts_rebuilt/app_ubi.bin, parts_rebuilt/data.bin
#
# How it works:
#   1. ubireader_extract_files each base volume -> directory trees.
#   2. Copy the overlay trees on top (cp -a, so staged files replace
#      same-named files and new files are added).
#   3. Optionally strip /data WiFi credentials + logs (--fresh-data).
#   4. mkfs.ubifs each tree with the base volume's own geometry (min I/O,
#      LEB size/count read from the base image via ubireader_utils_info,
#      so this adapts to any flash layout without hardcoding), then
#      ubinize into a raw UBI image the size of the original payload.
set -euo pipefail

WORK="${1:?usage: ubifs_rebuild.sh /work}"
PARTS="$WORK/parts"
OUT="$WORK/parts_rebuilt"
OVERLAY="$WORK/overlay"

echo "[ubifs] installing mtd-utils + python3-pip..."
apt-get update -qq
apt-get install -y -qq mtd-utils python3-pip >/dev/null

pip install --quiet --break-system-packages ubi-reader 2>/dev/null \
    || pip install --quiet ubi-reader
export PATH="$HOME/.local/bin:$PATH"

mkfs.ubifs --version >/dev/null 2>&1 || { echo "mkfs.ubifs missing" >&2; exit 1; }

mkdir -p "$OUT"

# rebuild <vol-name> <base-bin> <overlay-subdir> <fresh-data:0|1>
rebuild() {
    local vol="$1" base="$2" ovl="$3" fresh="$4"
    local ex="$WORK/extracted_$vol"
    rm -rf "$ex"
    echo "[ubifs] extracting $vol..."
    ubireader_extract_files "$base" -o "$ex" 2>/dev/null
    local tree
    tree="$(find "$ex" -mindepth 2 -maxdepth 2 -type d | head -1)"
    [ -n "$tree" ] || { echo "[ubifs] no volume dir found for $vol" >&2; exit 1; }
    echo "[ubifs]   tree: $tree"

    # Apply the overlay on top of the extracted tree.
    if [ -d "$OVERLAY/$ovl" ]; then
        cp -a "$OVERLAY/$ovl/." "$tree/"
        echo "[ubifs]   overlay applied: $ovl"
    fi

    # Fresh-data: wipe provisioning state so the device boots into
    # first-time BLE setup, and drop logs. Never touches /data/factory
    # (calibration data the firmware needs).
    if [ "$fresh" = "1" ] && [ "$vol" = "data" ]; then
        rm -rf "$tree/userconfig" "$tree/userdata/log" "$tree/.savegame"
        rm -f "$tree"/*.log "$tree"/mujina-minerd.bak-* "$tree"/mujina-minerd.log
        echo "[ubifs]   fresh-data: credentials/logs stripped"
        # The wipe removes userconfig/ entirely -- but wifi_bringup.sh
        # (run unconditionally by rcS) starts wpa_supplicant with
        # -c /data/userconfig/wpa_supplicant.conf, and with the config
        # missing the daemon exits immediately: wlan0 never comes up,
        # ble_setup's wpa_cli scan returns nothing (empty network list
        # in the app) and credential writes have nowhere to land.
        # Seed an empty-but-valid config, byte-identical in shape to
        # what ble_setup itself writes, so the daemon starts, the app's
        # scan populates, and provisioning works from a clean slate.
        mkdir -p "$tree/userconfig"
        # Seed the config wifi_bringup.sh requires. With WIFI_SSID passed in
        # (docker -e), bake real credentials in the exact format ble_setup
        # itself writes -- the daemon auto-associates at first boot, no app
        # needed. Otherwise seed empty-but-valid for BLE provisioning.
        if [ -n "${WIFI_SSID:-}" ]; then
            if [ -n "${WIFI_PASS:-}" ]; then
                printf 'ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\n\nnetwork={\n\tssid="%s"\n\tpsk="%s"\n\tkey_mgmt=WPA-PSK\n}\n' \
                    "$WIFI_SSID" "$WIFI_PASS" > "$tree/userconfig/wpa_supplicant.conf"
            else
                printf 'ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\n\nnetwork={\n\tssid="%s"\n\tkey_mgmt=NONE\n}\n' \
                    "$WIFI_SSID" > "$tree/userconfig/wpa_supplicant.conf"
            fi
            echo "[ubifs]   seeded /data/userconfig/wpa_supplicant.conf (wifi: SSID=$WIFI_SSID baked in)"
        else
            printf 'ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\n' > "$tree/userconfig/wpa_supplicant.conf"
            echo "[ubifs]   seeded /data/userconfig/wpa_supplicant.conf (empty -- BLE provisioning)"
        fi
    fi

    # Restore executable bits (2026-09-12): the extract step loses the
    # exec bits on base-image files (proved by diffing v3 against
    # alpha-v2: wifi_bringup.sh went 750 -> 644, so rcS's direct
    # execution failed with Permission denied and wpa_supplicant never
    # started -- empty WiFi scan list + every save reporting failed).
    # Only files staged fresh via the overlay kept their +x. Restore the
    # proven image's convention: 750 on everything under app_ubi
    # (scripts/binaries alike -- root-owned, nothing non-root reads
    # them), 755 on the data volume (alpha-v2's /data is uniformly
    # rwxr-xr-x).
    if [ "$vol" = "app_ubi" ]; then
        find "$tree" -type f -exec chmod 750 {} + 2>/dev/null || true
        [ -f "$tree/release/linux/app/mujina_display_startup.sh" ] && \
            chmod 755 "$tree/release/linux/app/mujina_display_startup.sh"
        echo "[ubifs]   exec bits restored on app_ubi tree (750, startup 755)"
    elif [ "$vol" = "data" ]; then
        find "$tree" -type f -exec chmod 755 {} + 2>/dev/null || true
        echo "[ubifs]   exec bits restored on data tree (755)"
    fi

    # Recipe: ubireader_utils_info reconstructs the ORIGINAL vendor
    # mkfs.ubifs + ubinize invocation from the base image's EC/VID headers
    # (compression, fanout, sub-pages, vid offset, image-seq, volume
    # name/id/size). Patch those files in place -- tree path, our ubifs
    # image path, output path -- drop `vol_flags = 0` (modern ubinize
    # rejects a zero flag value), then replay the script verbatim. The one
    # thing that legitimately changes is the ubifs payload itself.
    local info="$WORK/ubiinfo_$vol"
    local base_bytes
    base_bytes=$(stat -c%s "$base")
    rm -rf "$info"
    ubireader_utils_info -o "$info" "$base" >/dev/null 2>&1
    local imgdir create_sh ini_file
    imgdir="$(find "$info" -type d -name 'img-*' | head -1)"
    [ -n "$imgdir" ] || { echo "[ubifs] utils_info produced no img dir for $vol" >&2; exit 1; }
    create_sh="$(find "$imgdir" -name 'create_ubi_img-*.sh' | head -1)"
    ini_file="$(find "$imgdir" -name 'img-*.ini' | head -1)"
    [ -n "$create_sh" ] && [ -n "$ini_file" ] || { echo "[ubifs] missing create script/ini for $vol" >&2; exit 1; }

    sed -i "s|\$1|$tree|g" "$create_sh"
    sed -i "s|img-[0-9]*_0\.ubifs|$WORK/${vol}_ubifs.img|g" "$create_sh"
    sed -i "s|-o img-[0-9]*\.ubi|-o $OUT/$vol.bin|g" "$create_sh"
    sed -i "s|^image = .*|image = $WORK/${vol}_ubifs.img|" "$ini_file"
    sed -i '/^vol_flags = 0$/d' "$ini_file"
    echo "[ubifs]   replaying vendor recipe: $(grep 'mkfs.ubifs' "$create_sh" | head -1)"
    ( cd "$imgdir" && bash "$(basename "$create_sh")" )
    [ -f "$OUT/$vol.bin" ] || { echo "[ubifs] rebuild produced no $OUT/$vol.bin" >&2; exit 1; }
    local out_bytes
    out_bytes=$(stat -c%s "$OUT/$vol.bin")
    if [ "$out_bytes" -gt "$base_bytes" ]; then
        # Overflow: partition is a fixed-size payload; a bigger volume grows
        # the kdimg. Warn loudly (create() still embeds it; the flash tool
        # checks device capacity).
        echo "[ubifs] WARNING: rebuilt $vol ($out_bytes) larger than base ($base_bytes)" >&2
    fi
    echo "[ubifs]   wrote $OUT/$vol.bin ($out_bytes bytes)"
}

# KEEP_DATA=0 (default) -> fresh-data wipe ON; --keep-data (KEEP_DATA=1)
# -> preserve the base image's /data untouched.
rebuild app_ubi "$PARTS/app_ubi.bin" app_ubi 0
rebuild data "$PARTS/data.bin" data "$([ "${KEEP_DATA:-0}" = "1" ] && echo 0 || echo 1)"

echo "[ubifs] done."
