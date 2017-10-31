from CommandHelp import *
from CommandClear import *
from CommandExit import *
from ArpSpoofing import *
from DnsSpoofing import *
from SSLStrip import *

class Command :

    commandLine = {}

    def __init__(self) :

        commandModules = [CommandHelp, CommandClear, CommandExit, ArpSpoofing, DnsSpoofing, SSLStrip]

        for commandModule in commandModules :
            self.commandLine[commandModule.command] = [commandModule, commandModule.outline]

        while True :
            c = input("Command : ")
	    if c == None :
		c = ""
            if c == "help" :
                self.viewMenu()
            elif c.strip() == "" :
                pass
            else :
                obj = self.commandLine.get(c, [CommandErr])[0]()
                obj.run()
                del obj

    def viewMenu(self) :
        print("======== MENU ========")
        for key, value in self.commandLine.items() :
            print(key + "\t: " + value[1])
        print("======================")

class CommandErr :
    def run(self) :
        print("Error! Command is not exist!")

if __name__ == '__main__':
    command = Command()
