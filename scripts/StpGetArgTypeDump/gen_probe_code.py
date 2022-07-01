import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)
    
    names = []
    probeidx = 0
   
    for syscall in data:
        name = syscall[0]
        trimmed = name.lstrip("Nt").lstrip("Zw")
        if not (trimmed,name) in names:
            names.append((trimmed, name))
            
    for name, _ in names:
        print(f"Id{name} = {probeidx},")
        probeidx += 1

    print("\n\n")
    for name, original in names:
        print(f"case PROBE_IDS::Id{name}: return \"{original}\";")

    print("\n\n")
    for name, original in names:
        print(f"case PROBE_IDS::Id{name}: return make_span(arg_types<t{name}>::value.begin(), arg_types<t{name}>::value.end());")

    print("\n\n")
    for name, _ in names:
        print(f"g_Apis.pSetCallback(\"{name}\", true, PROBE_IDS::Id{name});")
        print(f"g_Apis.pSetCallback(\"{name}\", false, PROBE_IDS::Id{name});")
        
    print("\n\n")
    for name, _ in names:
        print(f"g_Apis.pUnsetCallback(\"{name}\", true);")
        print(f"g_Apis.pUnsetCallback(\"{name}\", false);")