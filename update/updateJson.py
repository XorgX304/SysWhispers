#!/usr/bin/env python3

#This script takes the two paramenters (1: VerionsName) (2:getSyscalls.exe output) and updates the json files acordingly, outputing to stdout (redirect to get it to a file)
#Currently it'll only be updating for hardcoded windows 10, as everything else should be locked in
#You must manually update prototypes.json to include new functions, this file will disregard any item not already in prototypes.json
#if you do add a completely new function you'll need to add its skeleton ot syscall_numbers.json as well
#you must also update syswhisper.py's self.version_syscall_map to include the new windows 10 version (https://docs.microsoft.com/en-us/windows/release-information/)

import sys
import json
import os
import re

protofile = "../data/prototypes.json"
syscallfile = "../data/syscall_numbers.json"

def usage():
    print("updateJson.py <Version name ex 2004> <getSyscalls.exe output file>")
    sys.exit(1)


if len(sys.argv) != 3:
    usage()

if not os.path.exists(sys.argv[2]):
    print("unable to read in your new syscalls file")
    usage()

with open(sys.argv[2]) as fp:
    newsyscalls = {}
    for line in fp.readlines():
        parts = re.split('[\t ]+', line)
        if(len(parts) != 3 or parts[0] == "SYSCALL"):
            continue
        newsyscalls[parts[2].strip('\n')] = int(parts[0], base=16)

if not os.path.exists(protofile):
    os.chdir("update")
    if not os.path.exists(protofile):
        print("Please run this script from the \"update\" directory")
        usage()

with open(protofile) as fp:
    proto = json.load(fp)

with open(syscallfile) as fp:
    syscalls = json.load(fp)

# print("prototypes\n")
# print("------------")
# print(proto)
# print("syscalls\n")
# print("------------")
# print(syscalls)

for func, num in newsyscalls.items():
    if(func in proto and func in syscalls):
        syscalls[func]["Windows 10"][sys.argv[1]] = num

print(json.dumps(syscalls, indent=2))


