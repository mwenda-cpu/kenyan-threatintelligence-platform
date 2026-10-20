#!/usr/bin/env python3
import io
path = "src/darkweb_scanner/dashboard/templates/index.html"
with open(path, "rb") as f:
    data = f.read()

lines = data.split(b"\n")

# Fix 1: Remove BOM from line 0 if present
if lines and lines[0].startswith(b"\xef\xbb\xbf"):
    lines[0] = lines[0][3:]
    print("Removed BOM from line 0")

# Fix 2: Remove broken duplicate lines
# Line 2 is the broken one: starts with BOM + !DOCTYPE html>
# Line 3 is also broken: <!DOCTYPE html> without meaningful content
# We need to remove all lines that start with !DOCTYPE html> (no <) after line 1
new_lines = [lines[0], lines[1]]  # Keep line 0 (<!DOCTYPE) and line 1 (<html lang="en">)

for i, line in enumerate(lines[2:], start=2):
    # Skip lines that start with BOM + !DOCTYPE
    if line.startswith(b"\xef\xbb\xbf"):
        continue
    # Skip lines that are exactly !DOCTYPE html> (broken duplicate)
    if line == b"!DOCTYPE html>":
        continue
    # Keep other lines
    new_lines.append(line)

print("After 2nd fix:")
for i, line in enumerate(new_lines[:5]):
    print(f"  Line {i}: {line[:20].hex()} -> {line[:20]}")

new_data = b"\n".join(new_lines) + b"\n"
with open(path, "wb") as f:
    f.write(new_data)

print("Done")
print("Final first 30 bytes:", new_data[:30].hex())
print("Starts with <!DOCTYPE:", new_data.startswith(b"<!DOCTYPE html>"))

