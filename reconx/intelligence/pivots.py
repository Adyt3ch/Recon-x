"""ASN, RDAP, and passive OSINT pivots.

Safety Rule: Pivots and discovered infrastructure are recorded as suggestions/observations only.
They are NEVER added to scope automatically.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from reconx.database.storage import utc_now_iso


def parse_rdap_response(data: dict[str, Any]) -> dict[str, str]:
    """Extract ASN, entity name, and CIDR range from RDAP JSON."""
    handle = data.get("handle", "")
    name = data.get("name", "")
    start_addr = data.get("startAddress", "")
    end_addr = data.get("endAddress", "")
    cidr_range = f"{start_addr} - {end_addr}".strip(" -")

    # Look for org or entity names
    org_name = name
    entities = data.get("entities", [])
    for ent in entities:
        roles = ent.get("roles", [])
        if "registrant" in roles or "administrative" in roles:
            vcard = ent.get("vcardArray", [])
            if len(vcard) > 1:
                for entry in vcard[1]:
                    if entry and entry[0] == "fn":
                        org_name = entry[3]
                        break

    return {
        "handle": handle,
        "name": org_name or name,
        "cidr_range": cidr_range,
    }


def parse_shodan_response(data: dict[str, Any]) -> dict[str, Any]:
    """Parse passive Shodan host response into observation summary."""
    asn = data.get("asn", "")
    org = data.get("org", "")
    ports = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    return {
        "asn": asn,
        "org": org,
        "ports": ports,
        "hostnames": hostnames,
        "source": "shodan",
    }


def record_asn_pivot(
    db: sqlite3.Connection,
    asset_id: int,
    rdap_info: dict[str, str],
) -> int:
    """Store ASN and network ownership in asset_relationships table."""
    now = utc_now_iso()
    handle = rdap_info.get("handle") or "Unknown"
    name = rdap_info.get("name") or "Unknown"
    cidr = rdap_info.get("cidr_range") or ""
    relation = f"asn_pivot:{handle} ({name}) {cidr}".strip()

    cursor = db.execute(
        """
        INSERT INTO asset_relationships (parent_asset_id, child_asset_id, relation, observed_at)
        VALUES (?, ?, ?, ?)
        """,
        (asset_id, asset_id, relation, now),
    )
    db.commit()
    return cursor.lastrowid
