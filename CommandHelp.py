class CommandHelp :
    command = "help"
    outline = "HELP"
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
