import io

path = 'c:/Users/comp/threatintel-platform/src/darkweb_scanner/dashboard/templates/index.html'
with io.open(path, 'r', encoding='utf-8') as f:
    c = f.read()

# Remove old hasData declaration and the duplicate old if block
old_block = """    const hasData = interesting.length > 0;

     // dirEnum is empty -> enum hasn't run yet
"""

# Check if old block exists
if old_block in c:
    c = c.replace(old_block, "", 1)
    print("Removed old hasData declaration")
else:
    print("Old hasData declaration not found - checking alternate")

# Remove the old if (!hasData) block that's AFTER the new code
old_if = """    if (!hasData) {
      return `<div style="text-align:center;padding:40px 20px">
        <div style="font-size:2rem;margin-bottom:12px"></div>
        <div style="font-weight:600;margin-bottom:6px">Directory enumeration not yet run</div>
        <div style="color:var(--muted);font-size:.83rem;margin-bottom:16px">Probes ${domain} and its IPs for exposed paths using a 70-entry wordlist.</div>
        <button class="btn btn-primary" onclick="triggerPortScan(${_dnsCurrent?.id}, 'dirs')"> Run Dir Enum</button>
      </div>`;
    }
    const target = dirEnum && dirEnum.target ? dirEnum.target : domain;"""

if old_if in c:
    c = c.replace(old_if, "    const target = dirEnum && dirEnum.target ? dirEnum.target : domain;", 1)
    print("Removed old if (!hasData) block")
else:
    print("Old if block not found")

with io.open(path, 'w', encoding='utf-8') as f:
    f.write(c)

print("Done")