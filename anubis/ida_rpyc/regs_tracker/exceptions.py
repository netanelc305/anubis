class UnmappedMemoryError(Exception):

    def __init__(self, address):
        self.address = address
        super().__init__(f'Unmapped memory at address: {hex(address)}')
