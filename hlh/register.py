
class Register:
    def __init__(self, value):
        self.value = value

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.start is None or key.stop is None:
                raise Exception("Failed trying to access")
            value = self.value >> key.start
            m = ((1 << (key.stop - key.start + 1))) - 1
            return value & m
        else:
            return int(self.value >> key) & 1

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            if key.start is None or key.stop is None:
                raise Exception("Failed trying to access")
            mask = (1 << key.start) - 1
            h_v = self.value >> (key.stop + 1)
            l_v = self.value & mask
            self.value = (h_v << (key.stop+1)) + (value << key.start) + l_v
        else:
            assert value in [0, 1]
            h_v = self.value >> (key + 1)
            mask = (1 << key) - 1
            l_v = self.value & mask
            self.value = (h_v << (key + 1)) + (value << key) + l_v

    def __trunc__(self):
        return self.value

    def __repr__(self):
        return self.value

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        return True if self.value == other else False

    def get(self):
        return self.value

