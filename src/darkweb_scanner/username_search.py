"""Username OSINT search across common platforms."""

import concurrent.futures

from .dashboard.http_client import safe_fetch

SITES = [
    ("GitHub", "https://github.com/{u}"),
    ("Twitter", "https://twitter.com/{u}"),
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("GitLab", "https://gitlab.com/{u}"),
    ("Medium", "https://medium.com/@{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
]


def _check(site, template, username):
    url = template.format(u=username)
    try:
        resp = safe_fetch(url, timeout=8)
        status = resp.get("status", 0)
        if status == 200:
            return {"site": site, "url": url, "status": "found"}
        return None
    except Exception:
        return None


def search_username(username):
    username = (username or "").strip()
    if not username:
        return {"error": "username required", "found": [], "checked": 0}
    found = []
    checked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_check, site, tpl, username) for site, tpl in SITES]
        for fut in concurrent.futures.as_completed(futures):
            checked += 1
            res = fut.result()
            if res:
                found.append(res)
    return {"found": found, "checked": checked}
