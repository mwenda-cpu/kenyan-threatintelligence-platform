# fix_emoji.py — replace corrupted emoji with ASCII labels
p = 'src/darkweb_scanner/dashboard/templates/index.html'

with open(p, 'r', encoding='utf-8', errors='replace') as f:
    text = f.read()

print(f"Original size: {len(text)}")

# Order matters: longest first
replacements = [
    ('🌏', 'EA'),      ('🌐', 'WWW'),    ('🕷️', 'CRWL'),
    ('🕷',  'CRWL'),   ('🕸',  'WEB'),    ('🎭', 'ACTOR'),
    ('💰',  'CRIM'),   ('📊',  'STAT'),   ('🧪', 'IOC'),
    ('🔍',  'SRCH'),   ('🔑',  'KEY'),    ('📁', 'DIR'),
    ('📄',  'DOC'),    ('📡',  'TG'),     ('💬', 'CHAT'),
    ('🎵',  'TT'),     ('📧',  'MAIL'),   ('📱', 'MOB'),
    ('🛡',  'SEC'),    ('⚠',   '[!]'),    ('✅', '[OK]'),
    ('❌',  '[X]'),    ('🚨',  '[!!]'),   ('💡', 'TIP'),
    ('🎯',  'TGT'),    ('☠️',  'SKULL'),  ('☠',  'SKULL'),
    ('✊',  'FIST'),   ('🏴',  'FLAG'),   ('🆘', '[SOS]'),
    ('🔒',  'LOCK'),   ('🔓',  'UNLOCK'), ('📜', 'CERT'),
    ('🔧',  'TOOL'),   ('📋',  'PST'),    ('📝', 'NOTE'),
    ('🧰',  'TOOLBOX'),('👤',  'USR'),    ('👥', 'USRS'),
    ('🏦',  'BNK'),    ('🏥',  'HOSP'),   ('🏛', 'GOV'),
    ('📥',  'IMP'),    ('📤',  'EXP'),    ('▶',  '>'),
    ('■',   '.'),      ('⏹',  'STOP'),   ('⏳', '...'),
    ('—',   '-'),      ('–',   '-'),      ('…', '...'),
    ('·',   '.'),      ('•',   '*'),
]

before_emoji = sum(text.count(a) for a, _ in replacements)

for bad, good in replacements:
    text = text.replace(bad, good)

# Now find remaining corrupted sequences and remove them
import re
# Match typical mojibake patterns: ðŸ... â€... âš...
text = re.sub(r'[ðâÂ][\u0080-\u00FF\u0100-\u017F]{1,4}', '', text)

# Any other non-ASCII? Strip
remaining = [c for c in text if ord(c) > 127]
print(f"Emoji replaced: {before_emoji}")
print(f"Remaining non-ASCII: {len(remaining)}")
if remaining:
    print("  Sample:", [f"U+{ord(c):04X}" for c in set(remaining)][:20])
    # Replace remaining with empty
    text = ''.join(c if ord(c) < 128 else '' for c in text)

with open(p, 'w', encoding='utf-8', newline='') as f:
    f.write(text)

print(f"New size: {len(text)}")
print("Done.")