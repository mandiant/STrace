import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)
    
    arg_set = set()
    for syscall in data:
        args = syscall[1] 
        for arg in args:
            arg_set.add(arg)
    for arg in arg_set:
        print(arg)
        