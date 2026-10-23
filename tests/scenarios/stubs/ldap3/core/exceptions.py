class LDAPException(Exception): pass
class LDAPBindError(LDAPException): pass
class LDAPCommunicationError(LDAPException): pass
class LDAPOperationResult(LDAPException):
    def __init__(self, result=None, description=None, dn=None, message=None, **kw):
        super().__init__(f"{description or result}: {message or ''}")
        self.result, self.description, self.dn, self.message = result, description, dn, message
