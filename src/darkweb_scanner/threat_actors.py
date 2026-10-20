"""
Threat actor profiles â€” Kenya / East Africa focused.

Schema matches the API contract expected by dashboard_routes.py.
Fields: name, slug, aliases, origin, type, motivation, sectors,
countries_targeted, targeting_sea, keywords, known_malware, ttps,
description, first_seen, last_seen, status, risk_level,
hit_count, is_custom, recent_hits.
"""

THREAT_ACTORS = [

    # â”€â”€ State-sponsored / APT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "name": "MuddyWater",
        "slug": "muddywater",
        "aliases": ["Static Kitten", "Mango Sandstorm", "Mercury", "Seedworm"],
        "origin": "Iran",
        "type": "nation-state",
        "motivation": "espionage",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["muddywater", "static kitten", "mango sandstorm", "seedworm"],
        "known_malware": ["PowGoop", "Mori", "Small Sieve", "Atera", "ScreenConnect"],
        "ttps": ["spear phishing", "RMM abuse", "PowerShell backdoors", "DNS tunneling", "living-off-the-land"],
        "description": (
            "Iranian MOIS-linked APT. Uses spear-phishing with legitimate RMM tools "
            "(ScreenConnect, Atera), PowerShell backdoors, and DNS tunneling. "
            "Targeting Kenyan government e-services (eCitizen, IFMIS) and Kenyan "
            "financial institutions including mobile money platforms and banks."
        ),
        "first_seen": "2017",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "APT39",
        "slug": "apt39",
        "aliases": ["Chafer", "Remexi", "ITG07", "Cadelspy"],
        "origin": "Iran",
        "type": "nation-state",
        "motivation": "espionage",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["apt39", "chafer", "remexi", "itg07"],
        "known_malware": ["Remexi", "Cadelspy", "TinyZbot"],
        "ttps": ["spear phishing", "custom backdoors", "credential theft", "keylogging"],
        "description": (
            "Iranian APT focused on long-term intelligence collection. Uses "
            "custom backdoors (Remexi, Cadelspy) and commercial RATs. "
            "Targeting Kenyan government portals (eCitizen, IFMIS) and Kenyan "
            "banking infrastructure for credential harvesting."
        ),
        "first_seen": "2014",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "Silent Librarian",
        "slug": "silent-librarian",
        "aliases": ["APT35", "Phosphorus", "Charming Kitten", "Mint Sandstorm"],
        "origin": "Iran",
        "type": "nation-state",
        "motivation": "espionage",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["apt35", "silent librarian", "charming kitten", "phosphorus"],
        "known_malware": ["HyperScrape", "PowerLess", "Sponsor"],
        "ttps": ["credential phishing", "social engineering", "fake login pages", "token theft"],
        "description": (
            "Iranian state-aligned group best known for academic credential "
            "phishing and social engineering. Now targeting Kenyan government "
            "e-services (eCitizen, IFMIS, iTax) and Kenyan banking sector "
            "employees with fake login pages."
        ),
        "first_seen": "2017",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "Kimsuky",
        "slug": "kimsuky",
        "aliases": ["Velvet Chollima", "Emerald Sleet", "Black Banshee", "Thallium"],
        "origin": "North Korea",
        "type": "nation-state",
        "motivation": "espionage",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["kimsuky", "velvet chollima", "emerald sleet", "thallium"],
        "known_malware": ["BabyShark", "AppleSeed", "SHARPEXT", "RandomQuery"],
        "ttps": ["spear phishing", "social engineering", "Chrome extension malware", "browser credential theft"],
        "description": (
            "DPRK reconnaissance-focused APT. Conducts spear-phishing against "
            "Kenyan government e-services (eCitizen, IFMIS, iTax) personnel and "
            "Kenyan financial institution employees using browser credential theft."
        ),
        "first_seen": "2012",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },

    # â”€â”€ Financially motivated / Ransomware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "name": "LockBit 3.0",
        "slug": "lockbit3",
        "aliases": ["LockBit Black", "Bitwise Spider"],
        "origin": "Russia / CIS",
        "type": "ransomware",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["lockbit", "lockbit3", "lockbit black"],
        "known_malware": ["LockBit 3.0 builder", "StealBit"],
        "ttps": ["double extortion", "RDP abuse", "Cobalt Strike", "vulnerability exploitation"],
        "description": (
            "Ransomware-as-a-Service operation. Has listed Kenyan financial institutions "
            "and logistics victims on its leak site. Uses double-extortion "
            "(encryption + data leak) against Kenyan banks, SACCOs, and government "
            "e-services portals (eCitizen, IFMIS, iTax). Disrupted by Operation "
            "Cronos (Feb 2024) but affiliate activity continues through rebranded variants."
        ),
        "first_seen": "2019",
        "last_seen": None,
        "status": "active",
        "risk_level": "critical",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "DragonForce",
        "slug": "dragonforce",
        "aliases": ["DragonForce East Africa"],
        "origin": "Kenya",
        "type": "hacktivist",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["dragonforce", "dragon force"],
        "known_malware": ["DragonForce ransomware (LockBit variant)"],
        "ttps": ["web defacement", "DDoS", "SQL injection", "ransomware deployment", "Telegram coordination"],
        "description": (
            "Kenyan-origin hacktivist-turned-ransomware group. Highly active in East Africa "
            "with documented attacks on Kenyan government infrastructure including eCitizen "
            "and IFMIS portals, and Kenyan financial institutions. Originally operated as "
            "hacktivists before shifting to financial extortion."
        ),
        "first_seen": "2021",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "ALPHV",
        "slug": "alphv",
        "aliases": ["BlackCat", "Noberus", "Sphynx"],
        "origin": "Russia / CIS",
        "type": "ransomware",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["alphv", "blackcat", "noberus"],
        "known_malware": ["BlackCat ransomware", "ExMatter"],
        "ttps": ["triple extortion", "SEO poisoning", "bring-your-own-vulnerable-driver", "Rust malware"],
        "description": (
            "Rust-based ransomware group. Conducted attacks against Kenyan financial institutions "
            "including banks and SACCOs. Uses triple extortion. Ceased operations in 2024 after "
            "affiliate exit scam, but source code remains in use by successor groups."
        ),
        "first_seen": "2021",
        "last_seen": "2024",
        "status": "inactive",
        "risk_level": "critical",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "Akira",
        "slug": "akira",
        "aliases": ["Storm-1567"],
        "origin": "Russia / CIS",
        "type": "ransomware",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["akira", "storm-1567"],
        "known_malware": ["Akira ransomware", "Megazord"],
        "ttps": ["VPN exploitation", "Cisco ASA abuse", "Fortinet abuse", "double extortion"],
        "description": (
            "Ransomware group exploiting VPN appliances for initial access. "
            "Has listed Kenyan financial and government entities on its leak site "
            "including banks, SACCOs, and e-services portals (eCitizen, IFMIS, iTax)."
        ),
        "first_seen": "2023",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "Hunters International",
        "slug": "hunters-international",
        "aliases": ["Hive successor"],
        "origin": "Russia / CIS",
        "type": "ransomware",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["hunters international", "hunters"],
        "known_malware": ["Hive-derived ransomware"],
        "ttps": ["double extortion", "Hive source code", "RDP abuse"],
        "description": (
            "Appeared after Hive's takedown, using rewritten Hive ransomware source. "
            "Active in double-extortion targeting Kenyan financial institutions "
            "and government e-services portals (eCitizen, IFMIS, iTax)."
        ),
        "first_seen": "2023",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "Qilin",
        "slug": "qilin",
        "aliases": ["Agenda"],
        "origin": "Russia / CIS",
        "type": "ransomware",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["qilin", "agenda ransomware"],
        "known_malware": ["Qilin ransomware (Go-based)"],
        "ttps": ["custom encryption", "RMM abuse", "double extortion"],
        "description": (
            "Rust-based ransomware written in Go. Targets Kenyan financial sector entities "
            "including banks, SACCOs, and mobile money platforms, plus government e-services "
            "(eCitizen, IFMIS, iTax) using custom encryption and double extortion."
        ),
        "first_seen": "2022",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "Silence",
        "slug": "silence",
        "aliases": ["Whisper Spider"],
        "origin": "Russia / CIS",
        "type": "cybercriminal",
        "motivation": "financial",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["silence", "whisper spider"],
        "known_malware": ["Truebot", "Silence.Downloader"],
        "ttps": ["ATM jackpotting", "SWIFT fraud", "spear phishing", "lateral movement"],
        "description": (
            "Financially motivated group specialising in ATM jackpotting and "
            "SWIFT interbank fraud. Has targeted Kenyan banks and SACCOs. "
            "Uses spear-phishing to gain network footholds in Kenyan financial "
            "institutions, then moves laterally to card processing systems."
        ),
        "first_seen": "2016",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },

    # â”€â”€ Hacktivists / Cyber-mercenaries â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "name": "Anonymous Sudan",
        "slug": "anonymous-sudan",
        "aliases": ["Storm-1359", "KillNet affiliate"],
        "origin": "Sudan / Russia-linked",
        "type": "hacktivist",
        "motivation": "ideological",
        "sectors": ["government", "financial", "media", "transport"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["anonymous sudan", "storm-1359", "killnet"],
        "known_malware": ["Skynet DDoS panel", "MHDDoS"],
        "ttps": ["DDoS-for-hire", "Layer 7 attacks", "botnet rental", "Telegram coordination"],
        "description": (
            "Pro-Russian hacktivist group conducting high-volume DDoS attacks "
            "on government and financial portals. Launched sustained attacks "
            "against Kenya's eCitizen platform and government services in "
            "2023-2024. Known victims include eCitizen and Govt e-services. "
            "Operates a DDoS-for-hire service under the "
            "'Skynet' brand."
        ),
        "first_seen": "2023",
        "last_seen": None,
        "status": "active",
        "risk_level": "critical",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
    {
        "name": "KillNet",
        "slug": "killnet",
        "aliases": ["KillMilk"],
        "origin": "Russia",
        "type": "hacktivist",
        "motivation": "ideological",
        "sectors": ["government", "financial", "telecoms"],
        "countries_targeted": ["Kenya", "East Africa"],
        "targeting_sea": True,
        "keywords": ["killnet"],
        "known_malware": ["DDoS tools", "Killnet botnet"],
        "ttps": ["DDoS", "defacement", "doxxing", "Telegram recruitment"],
        "description": (
            "Pro-Russian hacktivist collective conducting DDoS attacks on "
            "Kenyan government portals including eCitizen and IFMIS. "
            "Frequently overlaps with Anonymous Sudan in targeting Kenyan "
            "government services."
        ),
        "first_seen": "2022",
        "last_seen": None,
        "status": "active",
        "risk_level": "high",
        "hit_count": 0,
        "is_custom": False,
        "recent_hits": [],
    },
]
