import os
import secrets
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address


from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from database import get_connection

load_dotenv()

app = FastAPI(title="Sentinel Security API")

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False
)


def verify_api_key(key: str | None = Depends(api_key_header)):
    expected = os.environ["AGENT_API_KEY"]

    if not key or not secrets.compare_digest(key, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )


class SecurityEvent(BaseModel):
    timestamp: datetime
    hostname: str = Field(min_length=1, max_length=255)
    service: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    username: str | None = None
    source_ip: IPv4Address | IPv6Address | None = None
    source_port: int | None = Field(
        default=None, ge=1, le=65535
    )


@app.get("/health")
def health():
    return {"status": "running"}


@app.post("/events", status_code=201)
def create_event(
    event: SecurityEvent,
    _: None = Depends(verify_api_key)
):
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO events (
                        timestamp,
                        hostname,
                        service,
                        event_type,
                        username,
                        source_ip,
                        source_port
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        event.timestamp,
                        event.hostname,
                        event.service,
                        event.event_type,
                        event.username,
                        str(event.source_ip)
                        if event.source_ip else None,
                        event.source_port
                    )
                )

                event_id = cursor.fetchone()[0]

        return {
            "message": "Event stored successfully",
            "event_id": event_id
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Database operation failed"
        )


@app.get("/events")
def list_events(
    limit: int = 50,
    _: None = Depends(verify_api_key)
):
    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100"
        )

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, timestamp, hostname,
                       service, event_type,
                       username, source_ip, source_port
                FROM events
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,)
            )

            rows = cursor.fetchall()

    return [
        {
            "id": row[0],
            "timestamp": row[1],
            "hostname": row[2],
            "service": row[3],
            "event_type": row[4],
            "username": row[5],
            "source_ip": str(row[6])
            if row[6] else None,
            "source_port": row[7]
        }
        for row in rows
    ]