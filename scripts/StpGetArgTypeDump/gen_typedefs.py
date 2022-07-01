import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)
    
    args = None
    ret = None
    name = None
    
    state = 0 # 0 = entry syscall , 1 = exit syscall, 2 = print then reset to 0
    for syscall in data:
        if state == 2:
            argstr = "("
            for arg in args:
                argstr += arg + ","
            argstr = argstr[:len(argstr) -1] # remove last comma
            argstr += ")"
            print(f"typedef {ret} (NTAPI* t{name}) {argstr}")
            state = 0
    
        name = syscall[0]
        name = name.lstrip("Nt").lstrip("Zw")
        if state == 0:
            args = syscall[1]  
            state = 1
        elif state == 1:
            ret = syscall[1][0]
            state = 2
