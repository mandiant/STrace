import sys
import re
import json

argre = re.compile("args\[([0-9]+)\]:\s+(.*)")
entries = []

with open(sys.argv[1]) as f:
    syscall = ""
    state = 0
    types = []
        
    for line in f:
        if 'syscall' in line:
            syscall = line.split('syscall')[1].strip(' ').split(' ')[0]
            state = 1
            
        if (state == 1 or state == 2) and 'args[' in line:
            match = argre.search(line)
            if match:
                typ = match.group(2)
                if typ == "(unknown)":
                    typ = "/*Unknown*/ void*"
                elif typ == "userland (unknown)":
                    type = "/*Usermode Unknown*/ void*"
                types.append(typ)
                state = 2
        elif state == 2:
            entries.append((syscall, types))
            types = []
            state = 0;

with open(sys.argv[2], "w+") as out:            
    j = json.dumps(entries)
    out.write(j)