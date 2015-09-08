#!/usr/bin/python

import sys
import os
import re
import subprocess

def banner():
    print '''
        ------------------------------
        [[[ .so injector by Karimo ]]]
        ------------------------------
        '''

def usage():
    print '''
        Usage: %s PID SO ENTRYSYMBOL

        Please be aware that the selected process must be dinamiccally linked to libdl
        ''' % sys.argv[0]

def printerr(s):
    print "[-] %s" % s

def printok(s):
    print "[+] %s" % s
        
def is_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def extract_libdl_mapping(maps):
    regex = re.compile('^([a-z0-9]+)-[a-z0-9]+ r-x.+\s+([^\s]+libdl.+\.so)$')
    for map in maps:
        match = regex.match(map)
        if not match: continue
        return (match.group(2), match.group(1))
    return None

def get_func_offset(lib, sym, at_glibc = False):
    try:
        output = subprocess.check_output(("readelf -l %s" % lib).split(' '))
    except OSError:
        printerr("Failed to invoke readelf -l over %s" % lib)
        exit(-1)
    extractor = re.compile("LOAD\s+[^\s]+\s+([^\s]+).+?R E", re.DOTALL) # first LOAD executable region
    m = extractor.search(output)
    if not m:
        printerr("Failed to locate first LOAD executable region in %s" % lib)
        return None
    load_base = int(m.group(1), base = 16)
    try:
        output = subprocess.check_output(("readelf -s %s" % lib).split(' '))
    except OSError:
        printerr("Failed to invoke readelf -s over %s" % lib)
        exit(-1)
    extractor = re.compile("[0-9]+: ([a-z0-9]+) .+ %s%s$" % (sym, '@@GLIBC_.+' if at_glibc else ''))
    for symbol in output.split("\n"):
        m = extractor.search(symbol)
        if m: break
    if not m:
        printerr("Failed to locate %s in %s, %s GLIBC" % (sym, lib, 'at' if at_glibc else 'not at'))
        return None
    return int(m.group(1), base = 16) - load_base

def inject(so, entry, pid = 1):
    if not is_alive(pid):
        printerr('Selected process is not alive or you do not have permissions over it')
        exit(-1)
    try:
        f = open("/proc/%d/maps" % pid, 'r')
    except IOError:
        printerr("Failed to load map file for %d" % pid)
        exit(-1)
    maps = f.readlines()
    f.close()
    libdl = extract_libdl_mapping(maps)
    if libdl is None:
        printerr('Selected process is not linked to libdl')
        exit(-1)
    printok("Process %d maps %s at 0x%s" % (pid, libdl[0], libdl[1]))
    dlopen_offset = get_func_offset(libdl[0], 'dlopen', at_glibc = True)
    if not dlopen_offset:
        exit(-1)
    printok("Found dlopen offset at 0x%x" % dlopen_offset)
    dlsym_offset = get_func_offset(libdl[0], 'dlsym', at_glibc = True)
    if not dlsym_offset:
        exit(-1)
    printok("Found dlsym offset at 0x%x" % dlsym_offset)
    if not get_func_offset(so, entry):
        exit(-1)
    dlopen_address = hex(int(libdl[1], base = 16) + dlopen_offset)
    dlsym_address = hex(int(libdl[1], base = 16) + dlsym_offset)
    printok("Virtual Address of dlopen in %d is %s" % (pid, dlopen_address))
    printok("Virtual Address of dlsym in %d is %s" % (pid, dlsym_address))
    printok("Ready to inject, let's go. Invoking C injector...")
    printok("injector %d %s %s %s %s" % (pid, dlopen_address, dlsym_address, so, entry))
    os.system("injector %d %s %s %s %s" % (pid, dlopen_address, dlsym_address, so, entry))

if __name__ == '__main__':
    banner()
    if len(sys.argv) != 4:
        usage()
        exit(-1)
    inject(sys.argv[2], sys.argv[3], int(sys.argv[1]))
