import sys
import os
import re

def banner():
    print '''
        -----------------------------
        [[[ SO injector by Karimo ]]]
        -----------------------------
        '''

def usage():
    print '''
        Usage: %s PID

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


def inject(pid = 1):
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

if __name__ == '__main__':
    banner()
    if len(sys.argv) != 2:
        usage()
        exit(-1)
    inject(int(sys.argv[1]))
