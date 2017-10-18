import os
import subprocess
import sys

class CommandExit :
    command = "exit"
    outline = "Exit Application"
    manual = ""

    def run(self) :
        print("Bye")
        sys.exit()


if __name__ == '__main__':
    print(CommandModule.manual)
