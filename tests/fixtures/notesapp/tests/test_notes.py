from notesapp import notes


class Req:
    def __init__(self, token, args=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.args = args or {}


def test_list_only_own():
    status, body = notes.list_notes(Req("change-me-a"))
    assert status == 200 and all(n["owner"] == "alice" for n in body)
