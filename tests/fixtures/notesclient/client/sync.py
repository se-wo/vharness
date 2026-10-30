"""notesclient: syncs exported notes for a user by calling notesapp.export_note."""
from notesapp.notes import export_note


class Request:
    def __init__(self, token, name):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.args = {"name": name}


def sync_export(token, filename_from_server):
    # The filename comes from a remote server response.
    return export_note(Request(token, filename_from_server))
