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
        output = subprocess.check_output("readelf -s .dynsym %s" % lib)
    except OSError:
        printerr("Failed to invoke readelf -s .dynsym over %s" % lib)
        exit(-1)
    extractor = re.compile("^\d+: ([a-z0-9]+) .+ %s%s$" % (lib, '@@GLIBC_.+' if at_glibc else ''))
    m = extractor.match(output)
    if not m:
        printerr("Failed to locate %s in %s, %s GLIBC" % (sym, lib, 'at' if at_glibc else 'not at'))
        return None
    return m.group(1)

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
    printok("Found %s at %s" % (libdl[0], libdl[1]))
    dlopen_offset = get_func_offset(libdl[0], 'dlopen', at_glibc = True)
    if not dlopen_offset:
        printerr("Impossible to locate dlopen in %s" % libdl[0])
        exit(-1)
    printok("Found dlopen offset at %s" % dlopen_offset)
    dlsym_offset = get_func_offset(libdl[0], 'dlsym', at_glibc = True)
    if not dlsym_offset:
        printerr("Impossible to locate dlsym in %s" % libdl[0])
        exit(-1)
    printok("Found dlsym offset at %s" % dlopen_offset)
    if not get_func_offset(so, entry):
        printerr('Your .so does not appear to be sane')
        exit(-1)
    dlopen_address = hex(int(libdl) + int(dlopen_offset, base = 16))
    dlsym_address = hex(int(libdl) + int(dlsym, base = 16))
    printok("Virtual Address of dlopen in %d is %s" % (pid, dlopen_address))
    printok("Virtual Address of dlsym in %d is %s" % (pid, dlsym_address))
    printok("Ready to inject, let's go. Invoking C injector...")
    printok("injector %d %s %s %s %s" % (pid, dlopen_address, dlsym_address, so, entry))
    system("injector %d %s %s %s %s" % (pid, dlopen_address, dlsym_address, so, entry))

if __name__ == '__main__':
    banner()
    if len(sys.argv) != 4:
        usage()
        exit(-1)
    inject(sys.argv[2], sys.argv[3], int(sys.argv[1]))
