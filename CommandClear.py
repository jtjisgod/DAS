import os
import subprocess

class CommandClear :
    command = "clear"
    outline = "Clear Screen"
    manual = ""

    def run(self) :
        if os.name in ('nt','dos'):
            subprocess.call("cls")
        elif os.name in ('linux','osx','posix'):
            subprocess.call("clear")
        else:
            print("\n") * 120
        pass


if __name__ == '__main__':
    print(CommandModule.manual)
