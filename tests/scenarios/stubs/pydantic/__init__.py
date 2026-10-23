class BaseModel:
    def __init__(self, **kw):
        for k, v in kw.items(): setattr(self, k, v)
