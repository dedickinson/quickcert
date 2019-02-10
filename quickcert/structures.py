class CertificateType:
    def __init__(self, name: str, dir: str = None,
                 extensions=[]):
        self.name = name
        self.dir = dir
        self.extensions = extensions

        if not self.dir:
            self.dir = self.name
