from database import get_connection


def initialize_database():
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id BIGINT GENERATED ALWAYS
                        AS IDENTITY PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    hostname TEXT NOT NULL,
                    service TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    source_ip INET,
                    source_port INTEGER
                        CHECK (
                            source_port BETWEEN 1 AND 65535
                        ),
                    received_at TIMESTAMPTZ
                        NOT NULL DEFAULT NOW()
                )
            """)

    print("Database initialized successfully")


if __name__ == "__main__":
    initialize_database()