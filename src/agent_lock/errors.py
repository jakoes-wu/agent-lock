"""Exit-code errors. Codes: 0 ok, 1 failure, 2 bad args, 3 not installed, 4 unsupported."""


class AgentLockError(Exception):
    def __init__(self, message, code=1):
        super(AgentLockError, self).__init__(message)
        self.code = code


class UsageError(AgentLockError):
    def __init__(self, message):
        super(UsageError, self).__init__(message, 2)


class NotInstalled(AgentLockError):
    def __init__(self, message="agent-lock is not installed"):
        super(NotInstalled, self).__init__(message, 3)


class Unsupported(AgentLockError):
    def __init__(self, message):
        super(Unsupported, self).__init__(message, 4)
