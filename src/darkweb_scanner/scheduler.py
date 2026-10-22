"""
Scheduler — APScheduler-backed background jobs for the Threat Intel Platform.

Runs the key data-collection pipelines on a fixed interval (default 60 minutes)
without relying on system cron:

  - IOC scraper        (scrapers.ioc_scraper.run_ioc_scraper)
  - Ransomware liveness scraper (scrapers.ransomware_scraper.scrape_ransomware)
  - Kenyan context scraper (scrapers.context_scraper.scrape_context)

Jobs are one-shot functions (they loop until completed) so there is no
concurrency/overlap risk; APScheduler guarantees at-most-once semantics.
"""

import os

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from darkweb_scanner.storage import Storage

# ---------------------------------------------------------------------------
# Job registry
# ---------------------------------------------------------------------------
JOBS = {}  # name -> (module_path, func_name)
JOBS.update(
    {
        "ioc_scraper": (
            "darkweb_scanner.scrapers.ioc_scraper",
            "run_ioc_scraper",
        ),
        "ransomware_scraper": (
            "darkweb_scanner.scrapers.ransomware_scraper",
            "scrape_ransomware",
        ),
        "ke_context_scraper": (
            "darkweb_scanner.scrapers.context_scraper",
            "scrape_context",
        ),
    }
)

# Default interval: 60 minutes. Overridable via the SCHEDULER_INTERVAL_MINUTES
# environment variable for faster local iteration.
SCHEDULER_INTERVAL_MINUTES = int(
    os.environ.get("SCHEDULER_INTERVAL_MINUTES", "60")
)

_scheduler = None


def get_interval_trigger() -> IntervalTrigger:
    return IntervalTrigger(minutes=SCHEDULER_INTERVAL_MINUTES)


def _do_job(job_name: str):
    """Execute one scheduled job and log the result."""
    module_path, func_name = JOBS[job_name]
    try:
        module = __import__(module_path, fromlist=[func_name])
        func = getattr(module, func_name)
        storage = Storage()
        result = func(storage)
        print(
            f"[scheduler] [{job_name}] ok — {result}", flush=True
        )
    except Exception as exc:
        print(f"[scheduler] [{job_name}] FAILED: {exc}", flush=True)


def start():
    """
    Start the APScheduler background scheduler. Safe to call when the same
    app instance is created multiple times (idempotent). Never returns until
    the process exits.
    """
    # Ensure tables + any on-start DB bootstrap exist before scheduling jobs.
    Storage()

    global _scheduler
    if _scheduler is not None and _scheduler.running:
        print("[scheduler] already running — no re-start", flush=True)
        return

    _scheduler = BackgroundScheduler(daemon=True)
    for job_name in JOBS:
        _scheduler.add_job(
            _do_job,
            trigger=get_interval_trigger(),
            args=[job_name],
            id=job_name,
            replace_existing=True,
        )
    _scheduler.start()
    print(
        f"[scheduler] started — jobs={','.join(JOBS)} interval={SCHEDULER_INTERVAL_MINUTES} min",
        flush=True,
    )


def stop():
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        print("[scheduler] stopped", flush=True)


def is_running() -> bool:
    return _scheduler is not None and _scheduler.running
