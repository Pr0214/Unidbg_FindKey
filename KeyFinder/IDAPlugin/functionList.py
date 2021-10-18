import os
import time

import ida_ida
import ida_nalt
import idaapi
import idautils
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK


def getFunctionList():
    functionlist = ""
    maxAddress = ida_ida.inf_get_max_ea()
    for func in idautils.Functions(0, maxAddress):
        if len(list(idautils.FuncItems(func))) > 50:
            functionName = str(idaapi.ida_funcs.get_func_name(func))
            oneFunction = hex(func) + "!" + functionName + "\t\n"
            functionlist += oneFunction
    return functionlist


# 获取SO文件名和路径
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    filepath, filename = os.path.split(fullpath)
    return filepath, filename


class getFunctions(plugin_t):
    flags = PLUGIN_PROC
    comment = "getFunctions"
    help = ""
    wanted_name = "getFunctions"
    wanted_hotkey = ""

    def init(self):
        print("getFunctions(v0.1) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):

        so_path, so_name = getSoPathAndName()
        functionlist = getFunctionList()
        script_name = so_name.split(".")[0] + "_functionlist_" + str(int(time.time())) + ".txt"
        save_path = os.path.join(so_path, script_name)
        with open(save_path, "w", encoding="utf-8") as F:
            F.write(functionlist)
        F.close()
        print(f"location: {save_path}")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return getFunctions()