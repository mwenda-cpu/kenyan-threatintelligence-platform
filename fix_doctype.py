#!/usr/bin/env python3
import io
path = "src/darkweb_scanner/dashboard/templates/index.html"
with open(path, "rb") as f:
    data = f.read()

print("Before fix, first 60 bytes:", data[:60].hex())

# Remove BOM from the very beginning
if data.startswith(b"\xef\xbb\xbf"):
    data = data[3:]
    print("Removed BOM from start")

lines = data.split(b"\n")
print(f"Total lines: {len(lines)}")

# Print first 5 lines as hex
for i, line in enumerate(lines[:5]):
    print(f"  Line {i}: {line[:20].hex()} -> {line[:20]}")

# Fix 1: Line 0 should start with <!DOCTYPE
if lines and lines[0].startswith(b"\xef\xbb\xbf"):
    lines[0] = lines[0][3:]
    print("Line 0: removed BOM")

# Fix 2: Remove duplicate broken line where line[1] = !DOCTYPE html> (no <)
if len(lines) > 1 and lines[1].startswith(b"!DOCTYPE html>"):
    print("Removing broken duplicate line 1")
    lines.pop(1)

# Fix 3: Ensure line 0 starts with <!DOCTYPE html>
if lines and lines[0].startswith(b"<!DOCTYPE html>"):
    print("Line 0 OK: starts with <!DOCTYPE html>")
elif lines:
    print("LINE 0 RAW:", lines[0][:30])

new_data = b"\n".join(lines) + b"\n"

with open(path, "wb") as f:
    f.write(new_data)

print("After fix, first 30 bytes:", new_data[:30].hex())
print("Starts with correct doctype:", new_data.startswith(b"<!DOCTYPE html>"))

