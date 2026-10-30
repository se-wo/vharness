import os

EXPORT_DIR = os.environ.get("NOTES_EXPORT_DIR", "/var/lib/notesapp/exports")

USERS = {
    "alice": {"id": "alice", "token": os.environ.get("ALICE_TOKEN", "change-me-a")},
    "bob": {"id": "bob", "token": os.environ.get("BOB_TOKEN", "change-me-b")},
}

NOTES = {
    1: {"id": 1, "owner": "alice", "title": "alice private", "body": "alice secret"},
    2: {"id": 2, "owner": "bob", "title": "bob private", "body": "bob secret"},
}


def get(note_id):
    return NOTES.get(note_id)


def list_for(owner):
    return [n for n in NOTES.values() if n["owner"] == owner]


def delete(note_id):
    NOTES.pop(note_id, None)
