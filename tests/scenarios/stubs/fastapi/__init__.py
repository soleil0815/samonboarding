import types

class HTTPException(Exception):
    def __init__(self, status_code, detail=None):
        super().__init__(detail); self.status_code = status_code; self.detail = detail

class _Routes:
    def __init__(self, **kw):
        self.routes = []; self.mounts = {}; self.handlers = []; self.middlewares = []
    def _method(self, method):
        def deco(path, **kw):
            def wrap(fn):
                self.routes.append((method, path, fn.__name__)); return fn
            return wrap
        return deco
    @property
    def get(self): return self._method("GET")
    @property
    def post(self): return self._method("POST")
    @property
    def delete(self): return self._method("DELETE")
    def exception_handler(self, exc):
        def wrap(fn): self.handlers.append((exc, fn)); return fn
        return wrap
    def middleware(self, kind):
        def wrap(fn): self.middlewares.append(fn); return fn
        return wrap
    def add_middleware(self, cls, dispatch=None, **kw): self.middlewares.append(dispatch)
    def add_exception_handler(self, exc, fn): self.handlers.append((exc, fn))
    def mount(self, path, sub, name=None): self.mounts[path] = sub
    def include_router(self, r): self.routes.extend(r.routes)

class FastAPI(_Routes): pass
class APIRouter(_Routes): pass

def Depends(x=None): return x
def Cookie(default=None): return default
class Response:
    def __init__(self): self.cookies = {}; self.headers = {}
    def set_cookie(self, key, value, **kw): self.cookies[key] = (value, kw)
    def delete_cookie(self, key): self.cookies.pop(key, None)
class Request:
    def __init__(self, ip="10.0.0.1", scheme="http", path="/", headers=None, method="GET"):
        self.client = types.SimpleNamespace(host=ip); self.url = types.SimpleNamespace(scheme=scheme, path=path)
        self.headers = dict(headers or {}); self.method = method
        self.scope = {"headers": [(str(k).lower().encode(), str(v).encode()) for k, v in self.headers.items()]}
class BackgroundTasks:
    def __init__(self): self.tasks = []
    def add_task(self, fn, *a, **k): self.tasks.append((fn, a, k))
status = types.SimpleNamespace(HTTP_401_UNAUTHORIZED=401)
