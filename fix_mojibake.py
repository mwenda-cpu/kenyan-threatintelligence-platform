#!/usr/bin/env python3
"""
Reverse PowerShell 5.1 mojibake corruption.
Emoji bytes were read as cp1252 then written as UTF-8.
Reverse: encode as cp1252, then decode as UTF-8.
"""

import pathlib

path = pathlib.Path("src/darkweb_scanner/dashboard/templates/index.html")
text = path.read_text(encoding="utf-8")

print(f"Original size: {len(text)} chars")
print(f"Sample (should show mojibake): {text[text.find('hd-card-title')-30:text.find('hd-card-title')+30]!r}")

def fix_chunk(chars: str) -> str:
    """Try to reverse mojibake on a chunk of non-ASCII characters."""
    try:
        return chars.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return chars  # can't fix — leave alone

def fix_text(s: str) -> str:
    """Process the text in ASCII/non-ASCII chunks."""
    out = []
    chunk = []
    for ch in s:
        if ord(ch) < 128:  # ASCII
            if chunk:
                out.append(fix_chunk("".join(chunk)))
                chunk = []
            out.append(ch)
        else:
            chunk.append(ch)
    if chunk:
        out.append(fix_chunk("".join(chunk)))
    return "".join(out)

fixed = fix_text(text)

print(f"Fixed size: {len(fixed)} chars")
print(f"Sample (should show emoji): {fixed[fixed.find('hd-card-title')-30:fixed.find('hd-card-title')+30]!r}")

# Sanity checks
if "🌏" in fixed or "⚠" in fixed or "🕷" in fixed:
    print("✅ Emoji recovered")
else:
    print("⚠️  No known emoji found — the file may need manual inspection")
    print("   First non-ASCII chars found:", [c for c in fixed if ord(c) > 127][:20])

# Write back — UTF-8, no BOM, no newline conversion
with open(path, "w", encoding="utf-8", newline="") as f:
    f.write(fixed)

print(f"✅ Wrote {path}")