from . import notes

ROUTES = {
    ("GET", "/notes"): notes.list_notes,
    ("GET", "/notes/<id>"): notes.get_note,
    ("DELETE", "/notes/<id>"): notes.delete_note,
    ("GET", "/export"): notes.export_note,
}


def dispatch(request):
    """Route a request. Every route is reachable by any client over HTTP."""
    method, path = request.method, request.path
    if path.startswith("/notes/") and path.count("/") == 2:
        return ROUTES[(method, "/notes/<id>")](request, path.rsplit("/", 1)[1])
    return ROUTES[(method, path)](request)
