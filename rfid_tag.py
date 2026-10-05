#!/usr/bin/env python3
"""Interactive menu to read/write text on a MIFARE Classic tag with an MFRC522 on a Raspberry Pi 5.

Setup (the old RPi.GPIO does not work on the Pi 5; rpi-lgpio is a drop-in replacement):

    sudo apt install python3-spidev python3-rpi-lgpio
    sudo raspi-config  -> Interface Options -> SPI -> enable
    python3 -m venv --system-site-packages .venv && source .venv/bin/activate
    pip install -r requirements.txt

Wiring (physical/BOARD pin numbers):
    SDA/SS -> 24 (CE0)   SCK -> 23   MOSI -> 19   MISO -> 21
    RST    -> 22         GND -> 6    3.3V -> 1

Usage:
    python rfid_tag.py
"""
import json
import os
import time

from mfrc522 import MFRC522 as MFRC522Reader
KEY = [0xFF] * 6          # factory default Key A
DATA_BLOCKS = (8, 9, 10)  # sector 2 data blocks (16 bytes each)
TRAILER_BLOCK = 11        # sector 2 trailer - never written
MAX_LEN = 16 * len(DATA_BLOCKS)
SAVE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_tags.json")
DEFAULT_TIMEOUT = 15


def wait_for_tag(reader, timeout):
    """Return the tag UID (list of bytes) once a tag is selected, or None on timeout."""
    deadline = time.time() + timeout if timeout else None
    while deadline is None or time.time() < deadline:
        status, _ = reader.MFRC522_Request(reader.PICC_REQIDL)
        if status == reader.MI_OK:
            status, uid = reader.MFRC522_Anticoll()
            if status == reader.MI_OK:
                reader.MFRC522_SelectTag(uid)
                return uid
        time.sleep(0.1)
    return None


def authenticate(reader, uid):
    return reader.MFRC522_Auth(reader.PICC_AUTHENT1A, TRAILER_BLOCK, KEY, uid) == reader.MI_OK


def read_tag(reader, uid):
    if not authenticate(reader, uid):
        raise RuntimeError("Authentication failed (tag may use a non-default key)")
    data = []
    for block in DATA_BLOCKS:
        chunk = reader.MFRC522_Read(block)
        if not chunk:
            raise RuntimeError(f"Failed to read block {block}")
        data += chunk
    return bytes(data).rstrip(b"\x00 ").decode("ascii", errors="replace")


def write_tag(reader, uid, text):
    payload = text.encode("ascii").ljust(MAX_LEN, b" ")
    if not authenticate(reader, uid):
        raise RuntimeError("Authentication failed (tag may use a non-default key)")
    for i, block in enumerate(DATA_BLOCKS):
        reader.MFRC522_Write(block, list(payload[i * 16:(i + 1) * 16]))


def uid_str(uid):
    return ":".join(f"{b:02X}" for b in uid[:4])


def load_saved():
    try:
        with open(SAVE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_entry(uid, data):
    entries = load_saved()
    entries.append({"uid": uid_str(uid), "data": data, "saved": time.strftime("%Y-%m-%d %H:%M:%S")})
    with open(SAVE_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def ask_timeout():
    raw = input(f"Timeout in seconds [{DEFAULT_TIMEOUT}, 0 = wait forever]: ").strip()
    try:
        return float(raw) if raw else DEFAULT_TIMEOUT
    except ValueError:
        return DEFAULT_TIMEOUT


def scan(reader, timeout):
    print("Hold a tag near the reader (Ctrl+C to cancel)...")
    try:
        uid = wait_for_tag(reader, timeout)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return None
    if uid is None:
        print("Timed out - no tag detected.")
        return None
    print("UID:", uid_str(uid))
    return uid


def do_read(reader):
    uid = scan(reader, ask_timeout())
    if uid is None:
        return
    try:
        data = read_tag(reader, uid)
    except RuntimeError as exc:
        print("Error:", exc)
        return
    finally:
        reader.MFRC522_StopCrypto1()
    print("Data:", repr(data))
    if input("Save UID and data? [y/N]: ").strip().lower() == "y":
        save_entry(uid, data)
        print(f"Saved to {SAVE_FILE}")


def write_text(reader, text, timeout):
    uid = scan(reader, timeout)
    if uid is None:
        return
    try:
        write_tag(reader, uid, text)
        print("Written. Verify:", repr(read_tag(reader, uid)))
    except RuntimeError as exc:
        print("Error:", exc)
    finally:
        reader.MFRC522_StopCrypto1()


def get_text():
    text = input(f"Text to write (max {MAX_LEN} ASCII chars): ")
    if len(text) > MAX_LEN or not text.isascii():
        print(f"Text must be ASCII and at most {MAX_LEN} characters.")
        return None
    return text


def do_write(reader):
    text = get_text()
    if text is not None:
        write_text(reader, text, ask_timeout())


def do_write_saved(reader):
    entries = load_saved()
    if not entries:
        print("No saved entries yet.")
        return
    for i, e in enumerate(entries, 1):
        print(f"{i}. {e['uid']}  {e['data']!r}  ({e['saved']})")
    choice = input("Entry number to write to a tag (blank to cancel): ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(entries):
        return
    write_text(reader, entries[int(choice) - 1]["data"], ask_timeout())

def build_block0(uid4, manufacturer_bytes=None):
    """uid4: 4-byte UID. Returns the 16-byte block 0 payload."""
    if len(uid4) != 4:
        raise ValueError("UID must be 4 bytes for a Classic-compatible magic card")
    bcc = uid4[0] ^ uid4[1] ^ uid4[2] ^ uid4[3]
    # SAK/ATQA + manufacturer bytes - defaults are fine for most magic cards,
    # but you can copy the real values read from the original fob instead.
    tail = manufacturer_bytes or [0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    return list(uid4) + [bcc] + tail


def write_uid_gen2(reader, current_uid, new_uid4):
    """Writes a new UID into block 0. Only works on Gen2/CUID magic cards."""
    block0 = build_block0(new_uid4)
    # Sector 0 trailer is block 3, not block 11 - auth there, not on TRAILER_BLOCK
    if reader.MFRC522_Auth(reader.PICC_AUTHENT1A, 3, KEY, current_uid) != reader.MI_OK:
        raise RuntimeError("Auth on sector 0 failed - not a Gen2 card, or wrong key")
    reader.MFRC522_Write(0, block0)

def do_clone_uid(reader):
    print("Scan the ORIGINAL fob to read its UID...")
    src_uid = scan(reader, ask_timeout())
    if src_uid is None:
        return
    new_uid4 = src_uid[:4]
    reader.MFRC522_StopCrypto1()

    print("Now scan the BLANK magic card to write to...")
    dst_uid = scan(reader, ask_timeout())
    if dst_uid is None:
        return
    try:
        write_uid_gen2(reader, dst_uid, new_uid4)
        print("UID written:", uid_str(new_uid4))
    except RuntimeError as exc:
        print("Error:", exc)
    finally:
        reader.MFRC522_StopCrypto1()

def main():
    reader = MFRC522Reader()
    actions = {"1": do_read, "2": do_write, "3": do_write_saved}
    try:
        while True:
            print("\n=== MFRC522 Menu ===")
            print("1. Read tag")
            print("2. Write tag")
            print("3. Write a saved entry's data to a tag")
            print("4. Quit")
            try:
                choice = input("> ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if choice == "4":
                break
            action = actions.get(choice)
            if action:
                action(reader)
            else:
                print("Invalid choice.")
    finally:
        reader.Close_MFRC522()


if __name__ == "__main__":
    main()
