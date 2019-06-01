"""General utility classes
"""


class Tree:
    """Basic tree structure with handy formatting

        I'm sorry that this is a concrete implementation
        inside an interfaces package
    """

    def __init__(self, name: str):
        self.name = str(name)
        self.child_nodes = []
        self.leaf_nodes = []
        self._dir_icon = '+'
        self._dir_join_icon = '-'
        self._dir_join_icon_base = '-'
        self._dir_suffix = '/'
        self._pipe_icon = '|'
        self._file_icon = '+'
        self._file_icon_base = '+'
        self._file_join_icon = '-'

    def add_child_node(self, tree: 'Tree'):
        """ Adds a child node (which is itself a tree)

            :param Tree tree: The child node being added
        """
        self.child_nodes.append(tree)

    def add_leaf_node(self, name: str):
        """ Adds a leaf node

            :param str name: The value of the leaf node
        """
        self.leaf_nodes.append(name)

    @staticmethod
    def transform(tree: 'Tree') -> dict:
        if isinstance(tree, Tree):
            return {
                'name': tree.name,
                'leaf_nodes': tree.leaf_nodes,
                'child_nodes': [Tree.transform(n) for n in tree.child_nodes]
            }

    def _print_node(
            self,
            padding_char=' ',
            padding_width=0,
            include_leaves=True,
            include_root=True,
            compact=False) -> str:
        padding = padding_char * padding_width

        if include_root:
            if len(self.child_nodes):
                join_icon = self._dir_icon + self._dir_join_icon
            else:
                join_icon = self._dir_icon + self._dir_join_icon_base

            output = "{}{} {}{}\n".format(
                padding, join_icon, self.name, self._dir_suffix)
        else:
            output = ''

        padding = padding_char * (padding_width + 2)

        if include_leaves:
            count = len(self.leaf_nodes)
            for leaf in self.leaf_nodes:
                count -= 1
                if count:
                    file_icon = self._file_icon
                else:
                    file_icon = self._file_icon_base

                output += "{}{}{}{}\n".format(padding,
                                              file_icon,
                                              self._file_join_icon,
                                              leaf)

        for node in self.child_nodes:
            if not compact:
                output += "{}{}\n".format(padding,
                                          self._pipe_icon)

            output += "{}".format(node._print_node(
                padding_width=padding_width + 2,
                include_leaves=include_leaves,
                compact=compact))

        return output

    def format_string(
            self,
            include_leaves=True,
            include_root=True,
            compact=False) -> str:
        return self._print_node(
            include_leaves=include_leaves,
            include_root=include_root,
            compact=compact)
