"""
Seed real-world Kenyan asset inventory into the `kenyan_assets` table.

Technologies commonly deployed across Kenya's government e-services,
mobile money operators, and financial institutions. Only assets are
seeded here — CVEs and alerts are populated by the live CVE ingestor.
"""

from __future__ import annotations

import logging

try:  # pragma: no cover - import path varies by invocation
    from ..storage import Base, KenyanAsset, Storage
except Exception:  # noqa: BLE001
    try:
        from darkweb_scanner.storage import Base, KenyanAsset, Storage
    except Exception:  # noqa: BLE001
        from src.darkweb_scanner.storage import Base, KenyanAsset, Storage

logger = logging.getLogger(__name__)

# (product_name, vendor, affected_versions, sector)
KENYAN_ASSETS = [
    # Government
    ("Nginx", "Nginx, Inc.", "1.20 - 1.24", "gov"),
    ("Apache HTTP Server", "Apache Software Foundation", "2.4.41 - 2.4.54", "gov"),
    ("Microsoft Exchange", "Microsoft", "2016, 2019, 2022", "gov"),
    ("Fortinet FortiWeb", "Fortinet", "6.0 - 7.0", "gov"),
    ("Cisco VPN (AnyConnect)", "Cisco", "4.9 - 5.0", "gov"),
    ("Microsoft SharePoint", "Microsoft", "2016, 2019", "gov"),
    ("Apache Tomcat", "Apache Software Foundation", "8.5 - 9.0", "gov"),
    ("Microsoft SQL Server", "Microsoft", "2016 - 2019", "gov"),
    ("Oracle Database", "Oracle", "12c - 19c", "gov"),
    ("SAP ERP", "SAP", "ECC 6.0, S/4HANA", "gov"),
    # Banking
    ("Nginx", "Nginx, Inc.", "1.20 - 1.24", "bank"),
    ("Apache HTTP Server", "Apache Software Foundation", "2.4.41 - 2.4.54", "bank"),
    ("Microsoft Exchange", "Microsoft", "2016, 2019, 2022", "bank"),
    ("Fortinet FortiGate", "Fortinet", "6.4 - 7.2", "bank"),
    ("Palo Alto Firewall", "Palo Alto Networks", "9.0 - 10.1", "bank"),
    ("Oracle Database", "Oracle", "12c - 19c", "bank"),
    ("IBM WebSphere", "IBM", "8.5 - 9.0", "bank"),
    ("F5 BIG-IP", "F5 Networks", "14.1 - 16.1", "bank"),
    ("Microsoft SQL Server", "Microsoft", "2017 - 2022", "bank"),
    ("Active Directory", "Microsoft", "2012 - 2022", "bank"),
    # Mobile Money
    ("Apache Kafka", "Apache Software Foundation", "2.8 - 3.4", "mobile_money"),
    ("MongoDB", "MongoDB, Inc.", "4.4 - 6.0", "mobile_money"),
    ("Nginx", "Nginx, Inc.", "1.20 - 1.24", "mobile_money"),
    ("Java (OpenJDK)", "Oracle", "8, 11, 17", "mobile_money"),
    ("RabbitMQ", "Pivotal", "3.8 - 3.12", "mobile_money"),
    ("PostgreSQL", "PostgreSQL Global Dev Group", "12 - 15", "mobile_money"),
    ("Redis", "Redis Ltd", "6.0 - 7.0", "mobile_money"),
    ("Apache Camel", "Apache Software Foundation", "3.0 - 3.18", "mobile_money"),
    # Fintech
    ("Nginx", "Nginx, Inc.", "1.20 - 1.24", "fintech"),
    ("Apache HTTP Server", "Apache Software Foundation", "2.4.41 - 2.4.54", "fintech"),
    ("Microsoft Exchange", "Microsoft", "2016, 2019", "fintech"),
    ("PostgreSQL", "PostgreSQL Global Dev Group", "13 - 15", "fintech"),
    ("Elasticsearch", "Elastic", "7.10 - 8.8", "fintech"),
    ("Kubernetes", "Cloud Native Computing Foundation", "1.23 - 1.28", "fintech"),
    ("Docker", "Docker, Inc.", "20.10 - 24.0", "fintech"),
    ("HashiCorp Vault", "HashiCorp", "1.6 - 1.12", "fintech"),
    # Web Servers/Proxies
    ("Microsoft IIS", "Microsoft", "10.0", "gov"),
    ("Microsoft IIS", "Microsoft", "10.0", "bank"),
    # CMS
    ("WordPress", "WordPress Foundation", "6.x", "gov"),
    ("WordPress", "WordPress Foundation", "6.x", "media"),
    # VPN/Edge
    ("Citrix NetScaler", "Citrix", "13.x", "gov"),
    ("Citrix NetScaler", "Citrix", "13.x", "bank"),
    ("Citrix NetScaler", "Citrix", "13.x", "telecom"),
    # Enterprise Software
    ("Oracle WebLogic", "Oracle", "12c - 14c", "gov"),
    ("Oracle WebLogic", "Oracle", "12c - 14c", "bank"),
    # Mobile/Telecom
    ("Huawei", "Huawei", "various", "telecom"),
    ("Ericsson", "Ericsson", "various", "telecom"),
    ("M-Pesa API", "Safaricom", "v2", "mobile_money"),
    ("M-Pesa API", "Safaricom", "v2", "telecom"),
    ("Airtel Money API", "Airtel", "v1", "mobile_money"),
    ("Airtel Money API", "Airtel", "v1", "telecom"),
]


def seed_assets(storage=None) -> dict:
    if storage is None:
        storage = Storage()
    # Ensure the schema exists, but do not wipe unrelated tables.
    Base.metadata.create_all(storage.engine)
    # Reset only the Kenyan assets, preserving users, CVEs, and alerts.
    with storage.get_session() as session:
        session.query(KenyanAsset).delete()
        session.commit()
    inserted = 0
    for product_name, vendor, affected_versions, sector in KENYAN_ASSETS:
        storage.upsert_kenyan_asset(
            product_name=product_name,
            vendor=vendor,
            affected_versions=affected_versions,
            sector=sector,
        )
        inserted += 1
    logger.info("Seeded %d Kenyan assets", inserted)
    return {"inserted": inserted, "total": len(KENYAN_ASSETS)}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    storage = Storage()
    summary = seed_assets(storage)
    print(f"\nAsset seeding complete: {summary}")