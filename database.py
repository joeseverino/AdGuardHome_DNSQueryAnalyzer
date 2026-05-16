"""
DuckDB database module for AdGuard Home Log storage and querying.

This module provides:
- Database initialization and schema management
- Functions to insert raw log entries
- Query functions for raw logs and aggregated summaries
"""

import duckdb
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

# Database file location
SCRIPT_DIR = Path(__file__).parent
DB_FILE = SCRIPT_DIR / "AppData" / "adguard_logs.duckdb"

# Public suffix list for base domain extraction (common TLDs)
MULTI_PART_TLDS = {
    'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.kr', 'co.in',
    'org.uk', 'net.au', 'org.au', 'ac.uk', 'gov.uk', 'com.mx', 'com.cn',
    'cloudfront.net', 'amazonaws.com', 'azurewebsites.net', 'blob.core.windows.net',
    'cloudapp.azure.com', 's3.amazonaws.com', 'elasticbeanstalk.com',
    'herokuapp.com', 'appspot.com', 'firebaseapp.com', 'web.app',
    'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
    'github.io', 'gitlab.io', 'bitbucket.io',
}


def get_connection() -> duckdb.DuckDBPyConnection:
    """Get a connection to the DuckDB database."""
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    return duckdb.connect(str(DB_FILE))


def init_database():
    """Initialize the database schema."""
    conn = get_connection()

    # Create the condensed query logs table
    # Each row is unique by: date, ip, client, domain, query_type, client_protocol, upstream, is_filtered, filter_rule
    conn.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            date DATE NOT NULL,
            ip VARCHAR NOT NULL,
            client VARCHAR NOT NULL DEFAULT '',
            domain VARCHAR NOT NULL,
            query_type VARCHAR,
            client_protocol VARCHAR,
            upstream VARCHAR,
            is_filtered BOOLEAN DEFAULT FALSE,
            filter_rule TEXT,
            count INTEGER NOT NULL DEFAULT 1
        )
    """)

    # Create indexes for common query patterns
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_date ON query_logs(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON query_logs(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON query_logs(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_is_filtered ON query_logs(is_filtered)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_query_type ON query_logs(query_type)")

    # Hot table for timing-sensitive analysis (beaconing, interval patterns).
    # Kept separate from the condensed `query_logs` because the value here is
    # the per-event timestamp, which condensing destroys. Retention is short
    # (RAW_RETENTION_DAYS) — long enough to spot a recurring beacon, short
    # enough that storage stays bounded.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_queries (
            timestamp TIMESTAMPTZ NOT NULL,
            ip VARCHAR NOT NULL,
            client VARCHAR DEFAULT '',
            domain VARCHAR NOT NULL,
            query_type VARCHAR,
            is_filtered BOOLEAN DEFAULT FALSE,
            filter_rule TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_ip_ts ON raw_queries(ip, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_domain_ts ON raw_queries(domain, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_ts ON raw_queries(timestamp)")

    # Create a table to track last fetch timestamp
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fetch_metadata (
            key VARCHAR PRIMARY KEY,
            value VARCHAR
        )
    """)

    # Create client names table (IP to hostname mapping)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS client_names (
            ip VARCHAR PRIMARY KEY,
            hostname VARCHAR NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create ignored domains table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ignored_domains (
            domain VARCHAR PRIMARY KEY,
            added_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            notes VARCHAR
        )
    """)

    conn.close()
    print(f"Database initialized: {DB_FILE}")


def extract_base_domain(domain: str) -> str:
    """
    Extract the base domain from a full domain name.
    e.g., 'sub.example.co.uk' -> 'example.co.uk'
         'api.example.com' -> 'example.com'
    """
    if not domain:
        return domain

    domain = domain.lower().rstrip('.')
    parts = domain.split('.')

    if len(parts) <= 2:
        return domain

    # Check for multi-part TLDs
    for i in range(len(parts) - 1):
        potential_tld = '.'.join(parts[i:])
        if potential_tld in MULTI_PART_TLDS:
            if i > 0:
                return '.'.join(parts[i-1:])
            return potential_tld

    # Default: return last two parts
    return '.'.join(parts[-2:])


def parse_timestamp(ts_str: str) -> tuple[datetime, str]:
    """
    Parse AdGuard timestamp string to datetime and date string.
    Handles nanosecond precision by truncating to microseconds.

    Returns: (datetime, date_str)
    """
    # Format: 2025-12-03T20:51:20.119085476-06:00
    # Python only handles microseconds (6 digits), so truncate nanoseconds (9 digits)
    try:
        # Find the decimal point and timezone
        if '.' in ts_str:
            base, rest = ts_str.split('.', 1)
            # Find where the timezone starts (+ or - after the decimal)
            tz_pos = -1
            for i, c in enumerate(rest):
                if c in '+-' and i > 0:
                    tz_pos = i
                    break

            if tz_pos > 0:
                fractional = rest[:tz_pos][:6]  # Truncate to 6 digits (microseconds)
                tz = rest[tz_pos:]
                ts_str = f"{base}.{fractional}{tz}"

        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        # Normalize to system local TZ before extracting the date. Without
        # this, UTC-stamped queries logged late evening local time become
        # next-day rows in the DB and break "today" comparisons in the UI.
        # The container's TZ env var controls what "local" means.
        date_str = dt.astimezone().strftime('%Y-%m-%d')
        return dt, date_str
    except Exception:
        # Fallback: try to extract date from string
        date_str = ts_str[:10] if len(ts_str) >= 10 else 'unknown'
        return datetime.now(), date_str


def get_client_names_map(conn: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """Get a mapping of IP addresses to client names."""
    results = conn.execute("SELECT ip, hostname FROM client_names").fetchall()
    return {row[0]: row[1] for row in results}


# Batch size for chunked executemany. One mega-batch causes DuckDB to grind
# through a huge WAL transaction with no visible progress; chunking keeps
# memory flat, lets us print progress, and avoids the long stalls that
# previously made cold ingest look hung.
INSERT_BATCH_SIZE = 10_000


def _batch_executemany(conn, sql: str, rows: list, label: str) -> None:
    """Stream rows through executemany in fixed-size batches with progress."""
    total = len(rows)
    if total == 0:
        return
    for i in range(0, total, INSERT_BATCH_SIZE):
        batch = rows[i:i + INSERT_BATCH_SIZE]
        conn.executemany(sql, batch)
        done = i + len(batch)
        if done == total or done % (INSERT_BATCH_SIZE * 10) == 0:
            print(f"    {label}: {done:,} / {total:,}", flush=True)


def insert_log_entries(entries: list[dict], conn: Optional[duckdb.DuckDBPyConnection] = None) -> int:
    """
    Insert log entries into both query_logs (condensed) and raw_queries (hot).
    Call condense_logs() after to aggregate query_logs duplicates.

    Args:
        entries: List of log entry dictionaries from AdGuard
        conn: Optional existing connection (creates new one if not provided)

    Returns:
        Number of entries inserted
    """
    should_close = conn is None
    if conn is None:
        conn = get_connection()

    # Get client name mapping
    client_map = get_client_names_map(conn)

    condensed_rows = []
    raw_rows = []
    for entry in entries:
        ts_str = entry.get('T', '')
        dt, date_str = parse_timestamp(ts_str)

        result = entry.get('Result', {})
        rules = result.get('Rules', [])
        filter_rule = rules[0].get('Text', '') if rules else ''

        ip = entry.get('IP', '')
        client = client_map.get(ip, '')
        domain = entry.get('QH', '')
        query_type = entry.get('QT', '')
        is_filtered = result.get('IsFiltered', False)

        condensed_rows.append((
            date_str, ip, client, domain, query_type,
            entry.get('CP', ''), entry.get('Upstream', ''),
            is_filtered, filter_rule, 1,
        ))
        # raw_queries: keep per-event timestamp for beaconing detection.
        raw_rows.append((
            dt, ip, client, domain, query_type, is_filtered, filter_rule,
        ))

    _batch_executemany(conn, """
        INSERT INTO query_logs
        (date, ip, client, domain, query_type, client_protocol,
         upstream, is_filtered, filter_rule, count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, condensed_rows, "query_logs")

    _batch_executemany(conn, """
        INSERT INTO raw_queries
        (timestamp, ip, client, domain, query_type, is_filtered, filter_rule)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, raw_rows, "raw_queries")

    if should_close:
        conn.close()

    return len(condensed_rows)


# Retention window for the hot raw_queries table. Pruned on every fetch.
RAW_RETENTION_DAYS = 7


def prune_raw_queries(days_to_keep: int = RAW_RETENTION_DAYS) -> int:
    """Drop rows older than `days_to_keep` from raw_queries. Returns count deleted."""
    days = max(1, int(days_to_keep))
    conn = get_connection()
    try:
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM raw_queries WHERE timestamp < NOW() - INTERVAL '{days}' DAY"
        ).fetchone()
        to_delete = int(count_row[0]) if count_row and count_row[0] else 0
        if to_delete > 0:
            conn.execute(
                f"DELETE FROM raw_queries WHERE timestamp < NOW() - INTERVAL '{days}' DAY"
            )
        return to_delete
    finally:
        conn.close()


def condense_logs(conn: Optional[duckdb.DuckDBPyConnection] = None) -> dict:
    """
    Condense query_logs by aggregating duplicate rows.

    Groups by: date, ip, client, domain, query_type, client_protocol, upstream, is_filtered, filter_rule
    Sums the count column for each group.

    Returns:
        dict with 'rows_before', 'rows_after', 'total_count' for verification
    """
    should_close = conn is None
    if conn is None:
        conn = get_connection()

    # Get stats before
    rows_before = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()[0]
    total_count_before = conn.execute("SELECT SUM(count) FROM query_logs").fetchone()[0] or 0

    # Create condensed version in a temp table
    conn.execute("""
        CREATE TEMP TABLE query_logs_condensed AS
        SELECT
            date,
            ip,
            client,
            domain,
            query_type,
            client_protocol,
            upstream,
            is_filtered,
            filter_rule,
            SUM(count) as count
        FROM query_logs
        GROUP BY date, ip, client, domain, query_type, client_protocol, upstream, is_filtered, filter_rule
    """)

    # Replace original table
    conn.execute("DELETE FROM query_logs")
    conn.execute("""
        INSERT INTO query_logs
        SELECT * FROM query_logs_condensed
    """)
    conn.execute("DROP TABLE query_logs_condensed")

    # Get stats after
    rows_after = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()[0]
    total_count_after = conn.execute("SELECT SUM(count) FROM query_logs").fetchone()[0] or 0

    if should_close:
        conn.close()

    return {
        'rows_before': rows_before,
        'rows_after': rows_after,
        'total_count_before': total_count_before,
        'total_count_after': total_count_after,
        'count_match': total_count_before == total_count_after,
    }


def migrate_to_condensed_schema():
    """
    One-time migration from old schema (with timestamp, answer, etc.) to new condensed schema.
    """
    conn = get_connection()

    # Check if old schema exists (has 'timestamp' column)
    columns = conn.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'query_logs'
    """).fetchall()
    column_names = [c[0] for c in columns]

    if 'timestamp' not in column_names:
        print("Already using new schema, no migration needed.")
        conn.close()
        return

    print("Migrating to condensed schema...")

    # Get stats before
    rows_before = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()[0]
    print(f"Rows before migration: {rows_before:,}")

    # Create new condensed table from old data, joining with client_names
    conn.execute("""
        CREATE TABLE query_logs_new AS
        SELECT
            q.date,
            q.ip,
            COALESCE(c.hostname, '') as client,
            q.domain,
            q.query_type,
            q.client_protocol,
            q.upstream,
            q.is_filtered,
            COALESCE(q.filter_rule, '') as filter_rule,
            COUNT(*) as count
        FROM query_logs q
        LEFT JOIN client_names c ON q.ip = c.ip
        GROUP BY q.date, q.ip, c.hostname, q.domain, q.query_type, q.client_protocol,
                 q.upstream, q.is_filtered, q.filter_rule
    """)

    # Get stats for new table
    rows_after = conn.execute("SELECT COUNT(*) FROM query_logs_new").fetchone()[0]
    total_count = conn.execute("SELECT SUM(count) FROM query_logs_new").fetchone()[0]

    print(f"Rows after condensing: {rows_after:,}")
    print(f"Total count (should match rows_before): {total_count:,}")
    print(f"Compression ratio: {rows_before/rows_after:.1f}x")

    if total_count != rows_before:
        print("WARNING: Count mismatch! Aborting migration.")
        conn.execute("DROP TABLE query_logs_new")
        conn.close()
        return

    # Drop old table and rename new one
    conn.execute("DROP TABLE query_logs")
    conn.execute("ALTER TABLE query_logs_new RENAME TO query_logs")

    # Recreate indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_date ON query_logs(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON query_logs(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON query_logs(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_is_filtered ON query_logs(is_filtered)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_query_type ON query_logs(query_type)")

    print("Migration complete!")
    conn.close()


def update_client_names(ip_to_hostname: dict[str, str]):
    """Update the client names table with IP to hostname mappings."""
    conn = get_connection()

    for ip, hostname in ip_to_hostname.items():
        conn.execute("""
            INSERT OR REPLACE INTO client_names (ip, hostname, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """, [ip, hostname])

    conn.close()


def get_last_entry_date() -> Optional[str]:
    """Get the most recent date in the database."""
    conn = get_connection()
    result = conn.execute("""
        SELECT MAX(date) as max_date FROM query_logs
    """).fetchone()
    conn.close()

    if result and result[0]:
        return str(result[0])
    return None


def set_metadata(key: str, value: str):
    """Set a metadata value."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO fetch_metadata (key, value) VALUES (?, ?)
    """, [key, value])
    conn.close()


def get_metadata(key: str) -> Optional[str]:
    """Get a metadata value."""
    conn = get_connection()
    result = conn.execute("""
        SELECT value FROM fetch_metadata WHERE key = ?
    """, [key]).fetchone()
    conn.close()
    return result[0] if result else None


# ============================================================================
# Query Functions for Web Service
# ============================================================================

def query_client_summary(
    date: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    ip: Optional[str] = None,
    client: Optional[str] = None,
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    filter_rule: Optional[str] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query client summary (aggregated by date/IP/client/domain/type/protocol/filtered/filter_rule).
    Uses the condensed query_logs table which already has counts.
    """
    conn = get_connection()

    # Build WHERE clause
    conditions = []
    params = []

    if date:
        conditions.append("date = ?")
        params.append(date)
    if date_from:
        conditions.append("date >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("date <= ?")
        params.append(date_to)
    if ip:
        conditions.append("LOWER(ip) = LOWER(?)")
        params.append(ip)
    if client:
        conditions.append("LOWER(client) LIKE LOWER(?)")
        params.append(f"%{client}%")
    if domain:
        conditions.append("LOWER(domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(query_type) LIKE LOWER(?)")
        params.append(f"%{query_type}%")
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)
    if filter_rule:
        conditions.append("LOWER(filter_rule) LIKE LOWER(?)")
        params.append(f"%{filter_rule}%")

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # HAVING clause for count filters (applied after SUM)
    having_conditions = []
    having_params = []
    if count_gte is not None:
        having_conditions.append("SUM(count) >= ?")
        having_params.append(count_gte)
    if count_lte is not None:
        having_conditions.append("SUM(count) <= ?")
        having_params.append(count_lte)

    having_clause = " AND ".join(having_conditions) if having_conditions else "1=1"

    # Sort mapping
    sort_map = {
        'Date': 'date', 'IP': 'ip', 'client': 'client', 'QH': 'domain',
        'QT': 'query_type', 'CP': 'client_protocol', 'IsFiltered': 'is_filtered',
        'filterRule': 'filter_rule', 'count': 'total_count'
    }
    sort_col = sort_map.get(sort_by, 'total_count')
    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Base query - aggregate by the display grouping
    # Group by date/ip/client/domain/type/protocol/filtered/filter_rule
    base_query = f"""
        SELECT
            date,
            ip,
            client,
            domain,
            query_type,
            client_protocol,
            is_filtered,
            filter_rule,
            SUM(count) as total_count
        FROM query_logs
        WHERE {where_clause}
        GROUP BY date, ip, client, domain, query_type, client_protocol, is_filtered, filter_rule
        HAVING {having_clause}
    """

    # Count total groups
    count_result = conn.execute(f"SELECT COUNT(*) FROM ({base_query}) subq",
                                 params + having_params).fetchone()
    total = count_result[0]

    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    # Get paginated results
    results = conn.execute(f"""
        {base_query}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """, params + having_params + [page_size, offset]).fetchall()

    conn.close()

    records = []
    for row in results:
        records.append({
            'Date': str(row[0]) if row[0] else '',
            'IP': row[1],
            'client': row[2],
            'QH': row[3],
            'QT': row[4],
            'CP': row[5],
            'IsFiltered': row[6],
            'filterRule': row[7] or '',
            'count': row[8],
        })

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': records,
    }


def query_domain_summary(
    date: Optional[str] = None,
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query domain summary (aggregated by date/domain/type/protocol/filtered).
    Each row represents a unique combination of (Date, Domain, Type, Protocol, Filtered).
    Uses the condensed query_logs table which already has counts.
    """
    conn = get_connection()

    # Build WHERE clause
    conditions = []
    params = []

    if date:
        conditions.append("date = ?")
        params.append(date)
    if domain:
        conditions.append("LOWER(domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(query_type) LIKE LOWER(?)")
        params.append(f"%{query_type}%")
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # HAVING clause for count filters (applied after SUM)
    having_conditions = []
    having_params = []
    if count_gte is not None:
        having_conditions.append("SUM(count) >= ?")
        having_params.append(count_gte)
    if count_lte is not None:
        having_conditions.append("SUM(count) <= ?")
        having_params.append(count_lte)

    having_clause = " AND ".join(having_conditions) if having_conditions else "1=1"

    # Sort mapping
    sort_map = {
        'Date': 'date', 'QH': 'domain', 'QT': 'query_type', 'CP': 'client_protocol',
        'IsFiltered': 'is_filtered', 'count': 'total_count'
    }
    sort_col = sort_map.get(sort_by, 'total_count')
    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Query aggregated by date/domain/type/protocol/filtered
    base_query = f"""
        SELECT
            date,
            domain,
            query_type,
            client_protocol,
            is_filtered,
            SUM(count) as total_count
        FROM query_logs
        WHERE {where_clause}
        GROUP BY date, domain, query_type, client_protocol, is_filtered
        HAVING {having_clause}
    """

    # Count total
    count_result = conn.execute(f"SELECT COUNT(*) FROM ({base_query}) subq",
                                 params + having_params).fetchone()
    total = count_result[0]

    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    # Get paginated results
    results = conn.execute(f"""
        {base_query}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """, params + having_params + [page_size, offset]).fetchall()

    conn.close()

    records = []
    for row in results:
        records.append({
            'Date': str(row[0]) if row[0] else '',
            'QH': row[1],
            'QT': row[2],
            'CP': row[3],
            'IsFiltered': row[4],
            'count': row[5],
        })

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': records,
    }


def query_base_domain_summary(
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    max_count_gte: Optional[int] = None,
    max_count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query base domain summary (aggregated by base domain/type/protocol/filtered).
    Uses the condensed query_logs table which already has counts.
    """
    conn = get_connection()

    # DuckDB doesn't have our extract_base_domain function, so we need to do this differently
    # Fetch domains and compute base domain in Python

    conditions = []
    params = []

    if query_type:
        conditions.append("LOWER(query_type) LIKE LOWER(?)")
        params.append(f"%{query_type}%")
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Get daily counts per domain (using SUM since data is already condensed)
    results = conn.execute(f"""
        SELECT
            domain,
            query_type,
            client_protocol,
            is_filtered,
            date,
            SUM(count) as daily_count
        FROM query_logs
        WHERE {where_clause}
        GROUP BY domain, query_type, client_protocol, is_filtered, date
    """, params).fetchall()

    conn.close()

    # Aggregate by base domain in Python
    from collections import defaultdict
    base_domain_data = defaultdict(lambda: {'total': 0, 'daily': defaultdict(int)})

    for row in results:
        full_domain = row[0]
        qt = row[1]
        cp = row[2]
        is_filt = row[3]
        date = row[4]
        count = row[5]

        base = extract_base_domain(full_domain)
        key = (base, qt, cp, is_filt)

        base_domain_data[key]['total'] += count
        base_domain_data[key]['daily'][date] += count

    # Convert to records with filtering
    records = []
    for (base, qt, cp, is_filt), data in base_domain_data.items():
        total_count = data['total']
        max_count = max(data['daily'].values()) if data['daily'] else 0

        # Apply domain filter
        if domain and domain.lower() not in base.lower():
            continue
        # Apply count filters
        if count_gte is not None and total_count < count_gte:
            continue
        if count_lte is not None and total_count > count_lte:
            continue
        if max_count_gte is not None and max_count < max_count_gte:
            continue
        if max_count_lte is not None and max_count > max_count_lte:
            continue

        records.append({
            'QH': base,
            'QT': qt,
            'CP': cp,
            'IsFiltered': is_filt,
            'count': total_count,
            'maxCount': max_count,
        })

    # Sort
    sort_map = {'QH': 'QH', 'QT': 'QT', 'CP': 'CP', 'IsFiltered': 'IsFiltered',
                'count': 'count', 'maxCount': 'maxCount'}
    sort_key = sort_map.get(sort_by, 'count')
    records.sort(key=lambda x: (x[sort_key] is None, x[sort_key]), reverse=not sort_asc)

    # Paginate
    total = len(records)
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    paginated = records[offset:offset + page_size]

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': paginated,
    }


def get_database_stats() -> dict:
    """Get statistics about the database."""
    conn = get_connection()

    stats = {}

    # Total queries (sum of counts from condensed table)
    result = conn.execute("SELECT SUM(count) FROM query_logs").fetchone()
    stats['total_queries'] = result[0] or 0

    # Total rows (condensed)
    result = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()
    stats['total_rows'] = result[0]

    # Date range
    result = conn.execute("SELECT MIN(date), MAX(date) FROM query_logs").fetchone()
    stats['date_min'] = str(result[0]) if result[0] else None
    stats['date_max'] = str(result[1]) if result[1] else None

    # Unique IPs
    result = conn.execute("SELECT COUNT(DISTINCT ip) FROM query_logs").fetchone()
    stats['unique_ips'] = result[0]

    # Unique domains
    result = conn.execute("SELECT COUNT(DISTINCT domain) FROM query_logs").fetchone()
    stats['unique_domains'] = result[0]

    # Filtered percentage
    result = conn.execute("""
        SELECT
            SUM(CASE WHEN is_filtered THEN 1 ELSE 0 END) as filtered,
            COUNT(*) as total
        FROM query_logs
    """).fetchone()
    stats['filtered_count'] = result[0]
    stats['filtered_percentage'] = round(result[0] / result[1] * 100, 2) if result[1] > 0 else 0

    conn.close()
    return stats


# ============================================================================
# Delete Operations
# ============================================================================

def delete_logs_before_date(date: str) -> dict:
    """
    Delete all query_log records with date before the specified date.

    Args:
        date: Date string in YYYY-MM-DD format (exclusive - deletes records BEFORE this date)

    Returns:
        dict with rows_deleted and queries_deleted (sum of counts)
    """
    conn = get_connection()

    # Get counts before deletion
    result = conn.execute("""
        SELECT COUNT(*), COALESCE(SUM(count), 0)
        FROM query_logs
        WHERE date < ?
    """, [date]).fetchone()
    rows_to_delete = result[0]
    queries_to_delete = result[1]

    # Perform deletion
    conn.execute("DELETE FROM query_logs WHERE date < ?", [date])

    conn.close()

    return {
        'rows_deleted': rows_to_delete,
        'requests_deleted': queries_to_delete,
    }


def delete_logs_by_domain(domain: str) -> dict:
    """
    Delete all query_log records matching the specified domain (exact match).

    Args:
        domain: Domain to delete (exact match)

    Returns:
        dict with rows_deleted and queries_deleted (sum of counts)
    """
    conn = get_connection()

    # Get counts before deletion
    result = conn.execute("""
        SELECT COUNT(*), COALESCE(SUM(count), 0)
        FROM query_logs
        WHERE domain = ?
    """, [domain]).fetchone()
    rows_to_delete = result[0]
    queries_to_delete = result[1]

    # Perform deletion
    conn.execute("DELETE FROM query_logs WHERE domain = ?", [domain])

    conn.close()

    return {
        'rows_deleted': rows_to_delete,
        'requests_deleted': queries_to_delete,
    }


# ============================================================================
# Ignored Domains Management
# ============================================================================

def add_ignored_domain(domain: str, notes: str = None) -> bool:
    """
    Add a domain to the ignored_domains table.

    Args:
        domain: Domain to ignore
        notes: Optional notes about why it's ignored

    Returns:
        True if added, False if already exists
    """
    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO ignored_domains (domain, notes, added_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """, [domain, notes])
        conn.close()
        return True
    except Exception:
        conn.close()
        return False


def remove_ignored_domain(domain: str) -> bool:
    """
    Remove a domain from the ignored_domains table.

    Args:
        domain: Domain to remove from ignore list

    Returns:
        True if removed, False if not found
    """
    conn = get_connection()

    result = conn.execute("""
        DELETE FROM ignored_domains WHERE domain = ?
    """, [domain])

    # Check if any rows were affected
    deleted = conn.execute("SELECT changes()").fetchone()[0]

    conn.close()
    return deleted > 0


def get_ignored_domains(search: str = None) -> list[dict]:
    """
    Get all ignored domains with their log counts.

    Args:
        search: Optional wildcard search filter (case-insensitive)

    Returns:
        List of dicts with domain, added_at, notes, log_count
    """
    conn = get_connection()

    # Build query with optional search filter
    query = """
        SELECT
            i.domain,
            i.added_at,
            i.notes,
            COALESCE(SUM(q.count), 0) as log_count
        FROM ignored_domains i
        LEFT JOIN query_logs q ON LOWER(q.domain) = LOWER(i.domain)
    """
    params = []

    if search:
        query += " WHERE LOWER(i.domain) LIKE LOWER(?)"
        params.append(f"%{search}%")

    query += " GROUP BY i.domain, i.added_at, i.notes ORDER BY i.domain"

    results = conn.execute(query, params).fetchall()

    conn.close()

    return [
        {
            'domain': row[0],
            'added_at': row[1].isoformat() if row[1] else '',
            'notes': row[2] or '',
            'log_count': row[3],
        }
        for row in results
    ]


def get_ignored_domains_set() -> set[str]:
    """
    Get all ignored domains as a set for fast lookup.

    Returns:
        Set of domain strings
    """
    conn = get_connection()

    results = conn.execute("SELECT domain FROM ignored_domains").fetchall()

    conn.close()

    return {row[0] for row in results}


# ============================================================================
# Dashboard Queries
# ============================================================================
#
# These power the at-a-glance landing-page dashboard. All queries operate on
# the existing condensed `query_logs` table and the `ignored_domains` table.
# Daily granularity is the limit of the source data, so all "24h" framing is
# really "today vs yesterday."
#
# Base domain extraction in SQL is approximate (last two dot-segments) — it
# matches `extract_base_domain()` for typical cases but diverges on multi-part
# public-suffix TLDs (e.g. `co.uk`, `amazonaws.com`). Acceptable tradeoff for
# v1 to keep these queries pure SQL.


_BASE_DOMAIN_SQL = "regexp_extract(domain, '([^.]+\\.[^.]+)$')"


def dashboard_headline() -> dict:
    """
    Return KPI tiles for the dashboard hero row.

    Each tile carries a current value, a delta vs the prior period, and a
    30-day sparkline. Sparklines are zero-filled for missing days.
    """
    conn = get_connection()
    try:
        # Today + yesterday rollups in one trip
        row = conn.execute("""
            SELECT
                COALESCE(SUM(CASE WHEN date = CURRENT_DATE THEN count END), 0) AS q_today,
                COALESCE(SUM(CASE WHEN date = CURRENT_DATE - 1 THEN count END), 0) AS q_yest,
                COALESCE(SUM(CASE WHEN date = CURRENT_DATE AND is_filtered THEN count END), 0) AS b_today,
                COALESCE(SUM(CASE WHEN date = CURRENT_DATE - 1 AND is_filtered THEN count END), 0) AS b_yest,
                COUNT(DISTINCT CASE WHEN date = CURRENT_DATE THEN ip END) AS c_today,
                COUNT(DISTINCT CASE WHEN date = CURRENT_DATE - 1 THEN ip END) AS c_yest
            FROM query_logs
            WHERE date >= CURRENT_DATE - 1
        """).fetchone()  # headline today+yesterday rollup
        q_today, q_yest, b_today, b_yest, c_today, c_yest = row

        # 30-day sparkline series, zero-filled for missing days
        spark_rows = conn.execute("""
            WITH series AS (
                SELECT (CURRENT_DATE - i::INTEGER) AS date FROM range(0, 30) t(i)
            )
            SELECT
                s.date,
                COALESCE(SUM(q.count), 0) AS total,
                COALESCE(SUM(CASE WHEN q.is_filtered THEN q.count ELSE 0 END), 0) AS blocked,
                COUNT(DISTINCT q.ip) AS clients
            FROM series s
            LEFT JOIN query_logs q ON q.date = s.date
            GROUP BY s.date
            ORDER BY s.date ASC
        """).fetchall()

        queries_spark = [r[1] for r in spark_rows]
        block_rate_spark = [
            (r[2] / r[1] * 100.0) if r[1] else 0.0 for r in spark_rows
        ]
        clients_spark = [r[3] for r in spark_rows]

        # New base domains first seen today (excluding ignored)
        new_today_row = conn.execute(f"""
            WITH base AS (
                SELECT {_BASE_DOMAIN_SQL} AS base_domain, MIN(date) AS first_seen
                FROM query_logs
                WHERE domain LIKE '%.%'
                  AND domain NOT IN (SELECT domain FROM ignored_domains)
                GROUP BY 1
            )
            SELECT COUNT(*) FROM base
            WHERE first_seen = CURRENT_DATE AND base_domain != ''
        """).fetchone()
        new_today = new_today_row[0] if new_today_row else 0

        def pct_delta(curr, prev):
            if prev == 0:
                return None
            return round((curr - prev) / prev * 100.0, 1)

        block_rate_today = (b_today / q_today * 100.0) if q_today else 0.0
        block_rate_yest = (b_yest / q_yest * 100.0) if q_yest else 0.0

        return {
            "queries_today": {
                "value": int(q_today),
                "delta_pct": pct_delta(q_today, q_yest),
                "sparkline": queries_spark,
            },
            "block_rate": {
                "value": round(block_rate_today, 2),
                "blocked": int(b_today),
                "allowed": int(q_today - b_today),
                "delta_pct": pct_delta(block_rate_today, block_rate_yest),
                "sparkline": [round(x, 2) for x in block_rate_spark],
            },
            "active_clients_today": {
                "value": int(c_today),
                "delta_pct": pct_delta(c_today, c_yest),
                "sparkline": clients_spark,
            },
            "new_domains_today": {
                "value": int(new_today),
            },
        }
    finally:
        conn.close()


def dashboard_queries_over_time(days: int = 30) -> dict:
    """
    Daily query counts split by allowed vs blocked, zero-filled.

    Args:
        days: Number of days to include, ending today.
    """
    if days < 1:
        days = 1
    if days > 365:
        days = 365
    conn = get_connection()
    try:
        rows = conn.execute(f"""
            WITH series AS (
                SELECT (CURRENT_DATE - i::INTEGER) AS date FROM range(0, {days}) t(i)
            )
            SELECT
                s.date,
                COALESCE(SUM(CASE WHEN NOT q.is_filtered THEN q.count ELSE 0 END), 0) AS allowed,
                COALESCE(SUM(CASE WHEN q.is_filtered THEN q.count ELSE 0 END), 0) AS blocked
            FROM series s
            LEFT JOIN query_logs q ON q.date = s.date
            GROUP BY s.date
            ORDER BY s.date ASC
        """).fetchall()
        return {
            "dates": [str(r[0]) for r in rows],
            "allowed": [int(r[1]) for r in rows],
            "blocked": [int(r[2]) for r in rows],
        }
    finally:
        conn.close()


def dashboard_first_seen(limit: int = 50) -> dict:
    """
    Base domains that were first observed today, grouped by client+domain.

    This is the security-analyst panel: "what just started talking that has
    never talked before?" Excludes domains on the ignore list.
    """
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    conn = get_connection()
    try:
        rows = conn.execute(f"""
            WITH base AS (
                SELECT
                    client,
                    ip,
                    {_BASE_DOMAIN_SQL} AS base_domain,
                    date,
                    is_filtered,
                    count
                FROM query_logs
                WHERE domain LIKE '%.%'
                  AND domain NOT IN (SELECT domain FROM ignored_domains)
            ),
            first_seen AS (
                SELECT client, ip, base_domain, MIN(date) AS first_seen_date
                FROM base
                WHERE base_domain != ''
                GROUP BY client, ip, base_domain
            )
            SELECT
                COALESCE(NULLIF(fs.client, ''), fs.ip) AS client_name,
                fs.ip,
                fs.base_domain,
                fs.first_seen_date,
                COALESCE(SUM(b.count), 0) AS count_total,
                BOOL_OR(b.is_filtered) AS was_filtered_any
            FROM first_seen fs
            LEFT JOIN base b USING (client, ip, base_domain)
            WHERE fs.first_seen_date = CURRENT_DATE
            GROUP BY fs.client, fs.ip, fs.base_domain, fs.first_seen_date
            ORDER BY count_total DESC
            LIMIT {limit}
        """).fetchall()
        return {
            "items": [
                {
                    "client": r[0],
                    "ip": r[1],
                    "base_domain": r[2],
                    "first_seen": str(r[3]),
                    "count": int(r[4]),
                    "was_filtered": bool(r[5]),
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


def dashboard_top_filter_rules(days: int = 7, limit: int = 15) -> dict:
    """
    Top filter rules by total hits over the window.

    Surfaces which blocklist rules are pulling weight, and inversely makes it
    easier to spot rules that *aren't* firing (low position vs expectation).
    """
    if days < 1:
        days = 1
    if days > 90:
        days = 90
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    conn = get_connection()
    try:
        rows = conn.execute(f"""
            SELECT
                filter_rule,
                SUM(count) AS hits,
                COUNT(DISTINCT ip) AS clients_affected
            FROM query_logs
            WHERE is_filtered = TRUE
              AND date >= CURRENT_DATE - {days}
              AND filter_rule IS NOT NULL
              AND filter_rule != ''
            GROUP BY filter_rule
            ORDER BY hits DESC
            LIMIT {limit}
        """).fetchall()
        return {
            "window_days": days,
            "items": [
                {
                    "rule": r[0],
                    "hits": int(r[1]),
                    "clients_affected": int(r[2]),
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


def dashboard_top_blocked_clients(days: int = 7, limit: int = 10) -> dict:
    """
    Clients ranked by blocked-query volume over the window.

    A "blocked" query is one the filter matched (is_filtered = TRUE). High
    counts here mean either (a) the device is chatty toward ad/tracker/
    telemetry endpoints, or (b) something is misbehaving and worth a look.
    Both are useful signals.
    """
    if days < 1:
        days = 1
    if days > 90:
        days = 90
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    conn = get_connection()
    try:
        rows = conn.execute(f"""
            SELECT
                COALESCE(NULLIF(client, ''), ip) AS name,
                ip,
                SUM(CASE WHEN is_filtered THEN count ELSE 0 END) AS blocks,
                SUM(count) AS total,
                COUNT(DISTINCT CASE WHEN is_filtered THEN domain END) AS unique_blocked_domains
            FROM query_logs
            WHERE date >= CURRENT_DATE - {days}
            GROUP BY name, ip
            HAVING SUM(CASE WHEN is_filtered THEN count ELSE 0 END) > 0
            ORDER BY blocks DESC
            LIMIT {limit}
        """).fetchall()
        return {
            "window_days": days,
            "items": [
                {
                    "client": r[0],
                    "ip": r[1],
                    "blocks": int(r[2]),
                    "total": int(r[3]),
                    "block_pct": round(r[2] / r[3] * 100.0, 1) if r[3] else 0.0,
                    "unique_blocked_domains": int(r[4]),
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


def dashboard_top_blocked_domains(days: int = 7, limit: int = 10) -> dict:
    """
    Specific destinations that were blocked the most over the window.

    Distinct from top filter rules: one rule like `||doubleclick.net^` can
    block many subdomains; this surfaces the actual subdomains your devices
    are reaching for. Useful for "what's my network *actually* talking to
    that I don't want it to."
    """
    if days < 1:
        days = 1
    if days > 90:
        days = 90
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    conn = get_connection()
    try:
        rows = conn.execute(f"""
            SELECT
                domain,
                SUM(count) AS hits,
                COUNT(DISTINCT ip) AS clients_affected,
                MAX(filter_rule) AS sample_rule
            FROM query_logs
            WHERE date >= CURRENT_DATE - {days}
              AND is_filtered = TRUE
              AND domain != ''
            GROUP BY domain
            ORDER BY hits DESC
            LIMIT {limit}
        """).fetchall()
        return {
            "window_days": days,
            "items": [
                {
                    "domain": r[0],
                    "hits": int(r[1]),
                    "clients_affected": int(r[2]),
                    "sample_rule": r[3] or "",
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


def dashboard_query_type_distribution() -> dict:
    """
    DNS record-type mix for today.

    A healthy modern network is mostly A + AAAA + HTTPS. Unusual spikes in
    TXT, NULL, or rare types are a classic DNS-tunneling tell. The chart
    just shows the mix; you read the anomalies.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT
                COALESCE(NULLIF(query_type, ''), '?') AS type,
                SUM(count) AS hits
            FROM query_logs
            WHERE date = CURRENT_DATE
            GROUP BY type
            ORDER BY hits DESC
        """).fetchall()
        return {
            "items": [
                {"type": r[0], "hits": int(r[1])}
                for r in rows
            ],
        }
    finally:
        conn.close()


def dashboard_suspicious_subdomains(limit: int = 15) -> dict:
    """
    Today's queries with structural indicators of potential DNS tunneling
    or DGA-like behavior:
      - Total domain length > 60 chars
      - 7+ dot-segments (deep subdomain nesting)

    These are coarse heuristics — most hits are CDN noise and false positives.
    The point is to make the long-tail visible so a human can eyeball it.
    Real detection comes from entropy + n-gram scoring (iteration 2).
    """
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    conn = get_connection()
    try:
        rows = conn.execute(f"""
            SELECT
                domain,
                LENGTH(domain) AS domain_length,
                LENGTH(domain) - LENGTH(REPLACE(domain, '.', '')) AS dot_count,
                ip,
                COALESCE(NULLIF(client, ''), ip) AS client_name,
                SUM(count) AS hits,
                BOOL_OR(is_filtered) AS was_filtered
            FROM query_logs
            WHERE date = CURRENT_DATE
              AND (
                LENGTH(domain) > 60
                OR (LENGTH(domain) - LENGTH(REPLACE(domain, '.', ''))) >= 7
              )
              AND domain NOT IN (SELECT domain FROM ignored_domains)
            GROUP BY domain, ip, client_name
            ORDER BY domain_length DESC, hits DESC
            LIMIT {limit}
        """).fetchall()
        return {
            "items": [
                {
                    "domain": r[0],
                    "length": int(r[1]),
                    "dots": int(r[2]),
                    "ip": r[3],
                    "client": r[4],
                    "hits": int(r[5]),
                    "was_filtered": bool(r[6]),
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


# ============================================================================
# Findings (security detections)
# ============================================================================
#
# Findings transform the raw DNS log into ranked, MITRE-tagged detections.
# All detectors operate on today's data (or last 2 days for the chatty-client
# detector) using the same condensed `query_logs` table the dashboard uses.
#
# Severity philosophy: HIGH = "investigate this afternoon", MEDIUM = "look
# this week", LOW/INFO = "FYI". KNOWN_BENIGN_PARENTS keeps Teams routing,
# CDN edges, and reverse-DNS noise from drowning real signal — those still
# surface but get demoted to INFO so a HIGH means something.

KNOWN_BENIGN_PARENTS = {
    'amazonaws.com', 'cloudfront.net', 'cloudflare.com', 'akamai.net',
    'akamaihd.net', 'azureedge.net', 'azure.com', 'fastly.net',
    'googleusercontent.com', 'googleapis.com', 'office.net', 'office.com',
    'microsoft.com', 'sharepointonline.com', 'live.com', 'msftncsi.com',
    'apple.com', 'icloud.com', 'edgekey.net', 'edgesuite.net', 'windows.net',
    'a2z.com', 'amazon.com', 'gvt1.com', 'gvt2.com', '1e100.net',
    'akadns.net', 'trafficmanager.net',
    'in-addr.arpa', 'ip6.arpa',
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    from math import log2
    counts = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * log2(c / total) for c in counts.values())


def _detect_tunneling(conn) -> list[dict]:
    rows = conn.execute(f"""
        WITH today_long AS (
            SELECT
                domain,
                {_BASE_DOMAIN_SQL} AS base_domain,
                ip,
                COALESCE(NULLIF(client, ''), ip) AS client_name,
                count,
                is_filtered
            FROM query_logs
            WHERE date = CURRENT_DATE
              AND domain LIKE '%.%'
              AND LENGTH(domain) > 50
              AND domain NOT IN (SELECT domain FROM ignored_domains)
        )
        SELECT
            base_domain,
            client_name,
            ip,
            COUNT(DISTINCT domain) AS unique_subdomains,
            AVG(LENGTH(domain)) AS avg_length,
            MAX(LENGTH(domain) - LENGTH(REPLACE(domain, '.', ''))) AS max_dots,
            SUM(count) AS total_hits,
            BOOL_OR(is_filtered) AS any_filtered
        FROM today_long
        GROUP BY base_domain, client_name, ip
        HAVING COUNT(DISTINCT domain) >= 3
           AND AVG(LENGTH(domain)) > 55
           AND MAX(LENGTH(domain) - LENGTH(REPLACE(domain, '.', ''))) >= 5
           AND base_domain != ''
        ORDER BY total_hits DESC
        LIMIT 15
    """).fetchall()

    findings = []
    for i, r in enumerate(rows):
        parent, client_name, ip = r[0], r[1], r[2]
        unique_sub, avg_len, max_dots = int(r[3]), float(r[4]), int(r[5])
        hits, any_filtered = int(r[6]), bool(r[7])

        samples = [s[0] for s in conn.execute(f"""
            SELECT domain
            FROM query_logs
            WHERE date = CURRENT_DATE
              AND ip = ?
              AND {_BASE_DOMAIN_SQL} = ?
              AND LENGTH(domain) > 50
            GROUP BY domain
            ORDER BY LENGTH(domain) DESC
            LIMIT 3
        """, [ip, parent]).fetchall()]

        if parent in KNOWN_BENIGN_PARENTS:
            sev = "info"
        elif not any_filtered and hits > 100:
            sev = "high"
        else:
            sev = "medium"

        if sev == "high":
            action = ("Unknown parent + sustained long-subdomain volume + not "
                      "filtered — pivot on this client and treat the parent as a "
                      "candidate covert channel until proven otherwise.")
        elif sev == "info":
            action = ("Structure matches tunneling but parent is known SaaS infra "
                      "(e.g., Teams routing, CDN). Sanity-check once, then ignore.")
        else:
            action = ("Plausible but partially filtered or low-volume. Open the "
                      "client's full log and watch trend across days.")

        findings.append({
            "id": f"tunnel-{i}",
            "title": f"DNS tunneling pattern: {parent}",
            "severity": sev,
            "mitre": {"id": "T1071.004", "name": "Application Layer Protocol: DNS"},
            "summary": (
                f"{client_name} made {hits:,} queries to {unique_sub} long "
                f"subdomains under {parent} today (avg {avg_len:.0f} chars, "
                f"up to {max_dots} dots deep)."
            ),
            "evidence": [
                {"label": "Client", "value": client_name},
                {"label": "Parent domain", "value": parent, "mono": True},
                {"label": "Sample subdomains", "value": "\n".join(samples),
                 "mono": True, "block": True},
            ],
            "metrics": {
                "Queries": hits,
                "Unique subdomains": unique_sub,
                "Avg length": int(avg_len),
                "Max depth (dots)": max_dots,
                "Filtered": "yes" if any_filtered else "no",
            },
            "action": action,
            "drill": {"type": "client_summary",
                      "params": {"ip": ip, "qh": parent, "date": "CURRENT_DATE"}},
        })
    return findings


def _detect_dga(conn) -> list[dict]:
    rows = conn.execute(f"""
        SELECT
            {_BASE_DOMAIN_SQL} AS base_domain,
            domain,
            SUM(count) AS hits,
            BOOL_OR(is_filtered) AS any_filtered,
            ANY_VALUE(ip) AS sample_ip,
            COALESCE(ANY_VALUE(NULLIF(client, '')), ANY_VALUE(ip)) AS sample_client
        FROM query_logs
        WHERE date = CURRENT_DATE
          AND domain LIKE '%.%'
          AND domain NOT IN (SELECT domain FROM ignored_domains)
        GROUP BY base_domain, domain
    """).fetchall()

    from collections import defaultdict
    groups = defaultdict(lambda: {"labels": [], "domains": [], "hits": 0,
                                  "filtered": False, "client": "", "ip": ""})
    for parent, domain, hits, any_filtered, ip, client in rows:
        if not parent or parent == domain or not domain.endswith(parent):
            continue
        prefix = domain[:-(len(parent) + 1)]
        leftmost = prefix.split('.')[0] if prefix else ''
        if len(leftmost) < 6:
            continue
        g = groups[parent]
        g["labels"].append(leftmost)
        g["domains"].append(domain)
        g["hits"] += int(hits)
        g["filtered"] = g["filtered"] or bool(any_filtered)
        if not g["client"]:
            g["client"] = client
            g["ip"] = ip

    findings = []
    idx = 0
    for parent, g in sorted(groups.items(), key=lambda kv: -kv[1]["hits"]):
        labels = g["labels"]
        if len(labels) < 5:
            continue
        avg_entropy = sum(_shannon_entropy(l) for l in labels) / len(labels)
        avg_label_len = sum(len(l) for l in labels) / len(labels)
        if avg_entropy < 3.5 or avg_label_len < 10:
            continue

        if parent in KNOWN_BENIGN_PARENTS:
            sev = "info"
        elif avg_entropy > 4.0 and not g["filtered"]:
            sev = "high"
        else:
            sev = "medium"

        samples = sorted(set(g["domains"]), key=len, reverse=True)[:3]

        if sev == "high":
            action = ("High character randomness on a non-CDN parent is the DGA "
                      "signature. Pivot on the client and sandbox the parent.")
        elif sev == "info":
            action = ("Random-looking labels are normal for CDNs and cache busters. "
                      "Confirm vendor and ignore.")
        else:
            action = ("Random but modest volume or partially blocked. Re-check "
                      "tomorrow — DGAs typically cycle.")

        findings.append({
            "id": f"dga-{idx}",
            "title": f"DGA-like subdomains under {parent}",
            "severity": sev,
            "mitre": {"id": "T1568.002", "name": "Dynamic Resolution: DGA"},
            "summary": (
                f"{len(labels)} unique high-entropy subdomain labels under "
                f"{parent} today (avg entropy {avg_entropy:.2f} bits, avg "
                f"label length {avg_label_len:.0f})."
            ),
            "evidence": [
                {"label": "Client (sample)", "value": g["client"]},
                {"label": "Parent domain", "value": parent, "mono": True},
                {"label": "Sample subdomains", "value": "\n".join(samples),
                 "mono": True, "block": True},
            ],
            "metrics": {
                "Unique labels": len(labels),
                "Avg entropy": round(avg_entropy, 2),
                "Avg label length": int(avg_label_len),
                "Total hits": g["hits"],
                "Filtered": "yes" if g["filtered"] else "no",
            },
            "action": action,
            "drill": {"type": "client_summary",
                      "params": {"ip": g["ip"], "qh": parent, "date": "CURRENT_DATE"}},
        })
        idx += 1
        if idx >= 10:
            break
    return findings


def _detect_new_high_traffic(conn) -> list[dict]:
    rows = conn.execute(f"""
        WITH base AS (
            SELECT
                {_BASE_DOMAIN_SQL} AS base_domain,
                MIN(date) AS first_seen,
                SUM(CASE WHEN date = CURRENT_DATE THEN count ELSE 0 END) AS today_hits,
                BOOL_OR(date = CURRENT_DATE AND is_filtered) AS today_filtered
            FROM query_logs
            WHERE domain LIKE '%.%'
              AND domain NOT IN (SELECT domain FROM ignored_domains)
            GROUP BY 1
        )
        SELECT base_domain, first_seen, today_hits, today_filtered
        FROM base
        WHERE first_seen = CURRENT_DATE
          AND base_domain != ''
          AND today_hits >= 50
        ORDER BY today_hits DESC
        LIMIT 10
    """).fetchall()

    findings = []
    for i, (parent, first_seen, hits, filtered) in enumerate(rows):
        hits = int(hits)
        top = conn.execute(f"""
            SELECT
                COALESCE(NULLIF(client, ''), ip) AS name,
                ip,
                SUM(count) AS c
            FROM query_logs
            WHERE date = CURRENT_DATE
              AND {_BASE_DOMAIN_SQL} = ?
            GROUP BY name, ip
            ORDER BY c DESC
            LIMIT 1
        """, [parent]).fetchone()
        client_name = top[0] if top else "?"
        client_ip = top[1] if top else ""

        if parent in KNOWN_BENIGN_PARENTS:
            sev = "info"
        elif hits >= 500 and not filtered:
            sev = "medium"
        else:
            sev = "low"

        action = ("Unknown parent with day-one traction warrants a WHOIS + "
                  "reputation check before trusting it." if sev != "info"
                  else "Known infra spinning up a new edge node — usually benign.")

        findings.append({
            "id": f"new-{i}",
            "title": f"New domain with traffic today: {parent}",
            "severity": sev,
            "mitre": {"id": "T1583.001", "name": "Acquire Infrastructure: Domains"},
            "summary": (
                f"{parent} was first observed today and already saw "
                f"{hits:,} queries (top driver {client_name})."
            ),
            "evidence": [
                {"label": "Base domain", "value": parent, "mono": True},
                {"label": "First seen", "value": str(first_seen)},
                {"label": "Top client", "value": client_name},
                {"label": "Blocked today", "value": "yes" if filtered else "no"},
            ],
            "metrics": {"Queries today": hits},
            "action": action,
            "drill": {"type": "client_summary",
                      "params": {"ip": client_ip, "qh": parent, "date": "CURRENT_DATE"}},
        })
    return findings


def _detect_chatty_blocked_clients(conn) -> list[dict]:
    rows = conn.execute("""
        SELECT
            COALESCE(NULLIF(client, ''), ip) AS name,
            ip,
            SUM(count) AS total,
            SUM(CASE WHEN is_filtered THEN count ELSE 0 END) AS blocks,
            COUNT(DISTINCT CASE WHEN is_filtered THEN domain END) AS unique_blocked
        FROM query_logs
        WHERE date >= CURRENT_DATE - 1
        GROUP BY name, ip
        HAVING SUM(count) >= 500
           AND SUM(CASE WHEN is_filtered THEN count ELSE 0 END) * 1.0 / SUM(count) >= 0.5
        ORDER BY blocks DESC
        LIMIT 5
    """).fetchall()

    findings = []
    for i, (name, ip, total, blocks, uniq) in enumerate(rows):
        total, blocks, uniq = int(total), int(blocks), int(uniq)
        pct = blocks / total * 100.0

        top_blocked = conn.execute("""
            SELECT domain, SUM(count) AS c
            FROM query_logs
            WHERE date >= CURRENT_DATE - 1
              AND is_filtered = TRUE
              AND ip = ?
            GROUP BY domain
            ORDER BY c DESC
            LIMIT 3
        """, [ip]).fetchall()
        sample_blocked = "\n".join(f"{d}  ({int(c):,})" for d, c in top_blocked)

        sev = "medium" if pct >= 65 else "low"

        findings.append({
            "id": f"chatty-{i}",
            "title": f"High block-rate client: {name}",
            "severity": sev,
            "mitre": None,
            "summary": (
                f"{name} ran {total:,} queries in the last 2 days and "
                f"{pct:.0f}% were blocked ({blocks:,} blocks across {uniq} "
                f"unique domains)."
            ),
            "evidence": [
                {"label": "Client", "value": name},
                {"label": "IP", "value": ip, "mono": True},
                {"label": "Top blocked destinations", "value": sample_blocked,
                 "mono": True, "block": True},
            ],
            "metrics": {
                "Total queries": total,
                "Blocked": blocks,
                "Block rate": f"{pct:.1f}%",
                "Unique blocked domains": uniq,
            },
            "action": ("Either a chatty ad-tech device (typical for smart TVs / "
                       "IoT) or a compromised host. Cross-check the top destinations "
                       "against known adware/telemetry lists; if those look clean, "
                       "look closer."),
            "drill": {"type": "client_summary",
                      "params": {"ip": ip, "is_filtered": True}},
        })
    return findings


def _detect_rare_query_types(conn) -> list[dict]:
    rows = conn.execute("""
        SELECT
            COALESCE(NULLIF(query_type, ''), '?') AS qt,
            SUM(count) AS hits,
            COUNT(DISTINCT domain) AS unique_domains,
            COUNT(DISTINCT ip) AS unique_clients
        FROM query_logs
        WHERE date = CURRENT_DATE
          AND query_type IN ('TXT', 'NULL', 'ANY', 'AXFR')
        GROUP BY qt
        HAVING SUM(count) >= 30
        ORDER BY hits DESC
    """).fetchall()

    findings = []
    for i, (qt, hits, ud, uc) in enumerate(rows):
        hits, ud, uc = int(hits), int(ud), int(uc)
        if qt == "TXT" and hits >= 500:
            sev = "medium"
        elif qt in ("NULL", "ANY", "AXFR") and hits >= 100:
            sev = "medium"
        else:
            sev = "low"

        findings.append({
            "id": f"qtype-{i}",
            "title": f"Elevated {qt} record queries today",
            "severity": sev,
            "mitre": {"id": "T1071.004", "name": "Application Layer Protocol: DNS"},
            "summary": (
                f"{hits:,} {qt} queries across {ud} domains and {uc} clients. "
                f"TXT / NULL spikes are a classic DNS-tunneling indicator."
            ),
            "evidence": [
                {"label": "Record type", "value": qt},
                {"label": "Unique domains", "value": str(ud)},
                {"label": "Unique clients", "value": str(uc)},
            ],
            "metrics": {"Queries": hits},
            "action": ("Modern apps use TXT for SPF/DKIM and ACME — modest volume "
                       "is fine. Drill in if a single client/domain dominates the mix."),
            "drill": {"type": "client_summary",
                      "params": {"qt": qt, "date": "CURRENT_DATE"}},
        })
    return findings


def _detect_beaconing(conn, days: int = 2) -> list[dict]:
    """
    Detect periodic per-(client, base_domain) DNS patterns from raw_queries.

    Beaconing = roughly periodic queries to the same destination, the
    classic C2 callback shape. Implementation: pull events per pair from
    the lookback window, compute mean inter-arrival interval and the
    coefficient of variation (CV = stddev / mean). Low CV on a high-volume
    series is the signature.

    Requires the raw_queries table to have data; returns [] silently if it
    doesn't (e.g. brand-new install before the first fetch since the schema
    landed).
    """
    has_data = conn.execute(
        f"SELECT COUNT(*) FROM raw_queries WHERE timestamp >= NOW() - INTERVAL '{int(days)}' DAY"
    ).fetchone()
    if not has_data or has_data[0] == 0:
        return []

    pairs = conn.execute(f"""
        SELECT
            ip,
            COALESCE(NULLIF(client, ''), ip) AS client_name,
            {_BASE_DOMAIN_SQL} AS base_domain,
            COUNT(*) AS event_count,
            BOOL_OR(is_filtered) AS any_filtered
        FROM raw_queries
        WHERE timestamp >= NOW() - INTERVAL '{int(days)}' DAY
          AND domain LIKE '%.%'
          AND domain NOT IN (SELECT domain FROM ignored_domains)
        GROUP BY ip, client_name, base_domain
        HAVING COUNT(*) >= 20 AND base_domain != ''
        ORDER BY event_count DESC
        LIMIT 50
    """).fetchall()

    findings = []
    idx = 0
    for ip, client_name, base_domain, event_count, any_filtered in pairs:
        ts_rows = conn.execute(f"""
            SELECT timestamp
            FROM raw_queries
            WHERE timestamp >= NOW() - INTERVAL '{int(days)}' DAY
              AND ip = ?
              AND {_BASE_DOMAIN_SQL} = ?
            ORDER BY timestamp
        """, [ip, base_domain]).fetchall()
        timestamps = [r[0] for r in ts_rows]
        if len(timestamps) < 20:
            continue

        # Inter-arrival deltas in seconds. Drop sub-second gaps — those are
        # multi-record lookups (A + AAAA + HTTPS firing together), not beacons.
        intervals = []
        for i in range(1, len(timestamps)):
            dt_diff = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if dt_diff >= 1.0:
                intervals.append(dt_diff)
        if len(intervals) < 15:
            continue

        mean = sum(intervals) / len(intervals)
        if mean < 5 or mean > 7200:
            continue  # too tight or too loose to be interesting

        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = variance ** 0.5
        cv = stddev / mean if mean else 999.0

        if cv > 0.4:
            continue  # not regular enough

        if mean < 90:
            interval_str = f"~{mean:.0f}s"
        elif mean < 3600:
            interval_str = f"~{mean / 60:.1f} min"
        else:
            interval_str = f"~{mean / 3600:.1f} hr"

        if base_domain in KNOWN_BENIGN_PARENTS:
            sev = "info"
        elif cv < 0.15 and not any_filtered and mean < 1800:
            sev = "high"
        elif cv < 0.25:
            sev = "medium"
        else:
            sev = "low"

        if sev == "high":
            action = ("Tight periodicity + non-CDN parent + not filtered is the "
                      "textbook DNS-based C2 shape. Pivot on the client, capture the "
                      "destination for IOC enrichment, and check the host's process tree.")
        elif sev == "info":
            action = ("Regular interval but the parent is known SaaS infra — almost "
                      "certainly a health-check or telemetry heartbeat. Worth confirming "
                      "the pattern matches the vendor's documented cadence.")
        else:
            action = ("Periodic enough to surface but not tight enough for high "
                      "confidence. Real beacons persist — re-check tomorrow.")

        findings.append({
            "id": f"beacon-{idx}",
            "title": f"Periodic queries: {client_name} → {base_domain}",
            "severity": sev,
            "mitre": {"id": "T1071.004", "name": "Application Layer Protocol: DNS"},
            "summary": (
                f"{client_name} queried {base_domain} {len(timestamps):,} times "
                f"in the last {days}d at {interval_str} intervals "
                f"(jitter CV={cv * 100:.0f}%)."
            ),
            "evidence": [
                {"label": "Client", "value": client_name},
                {"label": "Destination", "value": base_domain, "mono": True},
                {"label": "Window", "value": f"{days} day(s)"},
                {"label": "First → last", "value":
                    f"{timestamps[0].astimezone().strftime('%Y-%m-%d %H:%M')} → "
                    f"{timestamps[-1].astimezone().strftime('%Y-%m-%d %H:%M')}"},
            ],
            "metrics": {
                "Events": len(timestamps),
                "Mean interval": interval_str,
                "Jitter (CV)": f"{cv * 100:.1f}%",
                "Filtered": "yes" if any_filtered else "no",
            },
            "action": action,
            "drill": {"type": "client_summary",
                      "params": {"ip": ip, "qh": base_domain}},
        })
        idx += 1
        if idx >= 15:
            break
    return findings


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _finding_sort_key(f: dict):
    sev = _SEVERITY_ORDER.get(f.get("severity"), 9)
    metrics = f.get("metrics", {}) or {}
    volume = 0
    for k in ("Queries", "Queries today", "Total queries", "Total hits", "Blocked"):
        v = metrics.get(k)
        if isinstance(v, int):
            volume = max(volume, v)
    return (sev, -volume)


def compute_findings() -> dict:
    """Run all detectors and return severity-sorted findings + summary counts."""
    conn = get_connection()
    try:
        all_findings = []
        for detector in (_detect_beaconing,
                         _detect_tunneling, _detect_dga,
                         _detect_new_high_traffic,
                         _detect_chatty_blocked_clients,
                         _detect_rare_query_types):
            try:
                all_findings.extend(detector(conn))
            except Exception as e:
                # One detector failure shouldn't kill the whole tab
                print(f"[findings] {detector.__name__} failed: {e}")

        all_findings.sort(key=_finding_sort_key)

        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

        return {
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "counts": counts,
            "findings": all_findings,
        }
    finally:
        conn.close()


if __name__ == "__main__":
    # Initialize database when run directly
    init_database()
    print("Database schema created successfully.")
