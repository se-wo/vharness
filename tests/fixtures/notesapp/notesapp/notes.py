import os

from . import storage
from .auth import current_user, require_owner


def list_notes(request):
    user = current_user(request)
    return 200, storage.list_for(user["id"])


def get_note(request, note_id):
    user = current_user(request)
    note = storage.get(int(note_id))
    if note is None:
        return 404, {"error": "not found"}
    return 200, note


def delete_note(request, note_id):
    user = current_user(request)
    note = storage.get(int(note_id))
    if note is None:
        return 404, {"error": "not found"}
    require_owner(user, note)
    storage.delete(note["id"])
    return 204, None


def export_note(request):
    user = current_user(request)
    name = request.args.get("name", "export.txt")
    path = os.path.join(storage.EXPORT_DIR, name)
    with open(path, "rb") as fh:
        return 200, fh.read()
