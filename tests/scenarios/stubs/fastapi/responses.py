class HTMLResponse: pass
class JSONResponse:
    def __init__(self, status_code=200, content=None): self.status_code = status_code; self.content = content
class PlainTextResponse:
    def __init__(self, content="", status_code=200, media_type=None, headers=None):
        self.body = content.encode("utf-8") if isinstance(content, str) else content
        self.status_code = status_code; self.media_type = media_type; self.headers = headers or {}
