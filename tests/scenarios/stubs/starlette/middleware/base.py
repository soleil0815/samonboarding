class BaseHTTPMiddleware:
    def __init__(self, app, dispatch=None): self.app = app; self.dispatch = dispatch
