# utils.py

from datetime import datetime, timedelta, timezone


def is_session_valid(session):
    expiration_time = timedelta(seconds=240) # 4 minutes

    now = datetime.now(timezone.utc)

    if session.created_at.tzinfo is None:
        session_created_at = session.created_at.replace(tzinfo=timezone.utc)
    else:
        session_created_at = session.created_at

    return now - session_created_at < expiration_time
