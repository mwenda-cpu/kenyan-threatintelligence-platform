
from darkweb_scanner.ke_context import KenyaContext

class FakeRow:
    def __init__(self, title, date_published, threat_type, summary, source_url, created_at, id):
        self.title = title
        self.date_published = date_published
        self.threat_type = threat_type
        self.summary = summary
        self.source_url = source_url
        self.created_at = created_at
        self.id = id

from datetime import date

# Raw filename as title
r1 = KenyaContext._advisory_to_dict(FakeRow("ca_cyber_advisory.pdf", date(2024, 3, 15), "phishing", "summary", "http://x", None, 1))
print("title with .pdf:", repr(r1["title"]))
print("date formatted:", repr(r1["date_published"]))

# Normal title (no extension)
r2 = KenyaContext._advisory_to_dict(FakeRow("CA Cyber Security Advisory", date(2024, 3, 15), "phishing", "summary", "http://x", None, 2))
print("normal title:", repr(r2["title"]))

# None title
r3 = KenyaContext._advisory_to_dict(FakeRow(None, None, "phishing", "summary", "http://x", None, 3))
print("none title:", repr(r3["title"]))

print("TITLE TEST PASSED")
