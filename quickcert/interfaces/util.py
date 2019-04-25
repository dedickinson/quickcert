from collections import defaultdict  

class Tree(dict):
    """
    See: https://stackoverflow.com/a/19829714
    """
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value

