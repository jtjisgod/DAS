class CommandModule :
    command = ""
    outline = ""
    manual = \
"""
=== <TITLE> ===
None
===============
"""

    def run(self) :
        pass


if __name__ == '__main__':
    print(CommandModule.manual)
