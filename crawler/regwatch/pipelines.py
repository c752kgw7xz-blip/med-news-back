import json
import os
import hashlib
import psycopg


def _dedupe_key(source: str, official_url: str, official_date: str) -> str:
    s = f"{source}|{official_url}|{official_date}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _raw_sha256(obj: dict) -> str:
    canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PostgresUpsertPipeline:
    def __init__(self):
        self.conn = None
        self.cur = None

    def open_spider(self, spider=None):
        dsn = os.environ.get("DATABASE_URL")
        if not dsn:
            raise RuntimeError("DATABASE_URL missing (needed for crawler)")
        self.conn = psycopg.connect(dsn)
        self.cur = self.conn.cursor()

    def close_spider(self, spider=None):
        if not self.conn or not self.cur:
            return
        try:
            self.conn.commit()
        finally:
            try:
                self.cur.close()
            finally:
                self.conn.close()

    def process_item(self, item, spider=None):
        if not self.conn or not self.cur:
            return item

        source = item.get("source")
        official_url = item.get("official_url")
        official_date = item.get("official_date")
        title_raw = item.get("title_raw")
        pdf_url = item.get("pdf_url")

        if not (source and official_url and official_date):
            return item

        dedupe_key = _dedupe_key(source, official_url, official_date)
        # raw_json : payload brut de l'item scrapy (hors champs internes Scrapy)
        raw_payload = {
            k: v for k, v in dict(item).items()
            if not k.startswith("_")
        }
        raw_json_str = json.dumps(raw_payload, ensure_ascii=False, default=str)
        sha256 = _raw_sha256(raw_payload)

        self.cur.execute(
            """
            INSERT INTO candidates (
              source, official_url, official_date, title_raw, pdf_url,
              raw_json, raw_sha256, dedupe_key, status
            )
            VALUES (%s, %s, %s::date, %s, %s, %s::jsonb, %s, %s, 'NEW')
            ON CONFLICT (dedupe_key) DO NOTHING
            """,
            (source, official_url, official_date, title_raw, pdf_url,
             raw_json_str, sha256, dedupe_key),
        )
        return item
