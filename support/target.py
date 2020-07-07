
class TargetService (object):

    def __init__ (self, port, service):
        self.port    = port
        self.service = service
        self.product = ''
        self.version = ''
        self.vuln    = []