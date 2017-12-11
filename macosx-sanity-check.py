#!/usr/bin/env python

#
# This tool verifies that a Mac OS X executable is well-formed and portable.
#
# It verifies that all the dependant libraries are present and that the full executable is backwards
# compatible with at least Mac OS X 10.5.
#
# Usage: macosx-sanity-check.py /path/to/executable
#
# Returns:
#   0 if the executable an all libraries are OK
#   != 0 and prints some textural description on error
#
# Author: Marius Kintel <marius@kintel.net>
#
# This script lives here:
# https://github.com/kintel/MacOSX-tools
#

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import os
import subprocess
import re
from distutils.version import StrictVersion

DEPLOYMENT_TARGET = StrictVersion('10.8')
ARCHITECTURE = 'x86_64'

DEBUG = False

cxxlib = None
executable_path = None
lc_rpath = None

def usage():
    print("Usage: " + sys.argv[0] + " <executable>", file=sys.stderr)
    sys.exit(1)

def get_deployment_target(otool_output):
    m = re.search("LC_VERSION_MIN_MACOSX.*\n(.*)\n\s+version (.*)", otool_output, re.MULTILINE)
    return m.group(2)

def get_rpath(otool_output):
    m = re.search("LC_RPATH\n(.*)\n\s+path ([^ ]+)", otool_output, re.MULTILINE)
    return m.group(2)

def get_load_commands(binary):
    p  = subprocess.Popen(["otool", "-l", binary], stdout=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    if p.returncode != 0: return None, stderr
    return stdout, None

# Returns dependent libraries as a list of library filenames
def get_libraries(binary):
    p = subprocess.Popen(["otool", "-L", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, err = p.communicate()
    if p.returncode != 0: 
        print("Failed with return code " + str(p.returncode) + ":")
        print(err)
        return None
    return output.split('\n')

def get_global_symbols(binary):
    p  = subprocess.Popen(["nm", "-g", binary], stdout=subprocess.PIPE, universal_newlines=True)
    stdout, stderr  = p.communicate()
    if p.returncode != 0: return None, stderr
    return stdout, None

def verify_architecture(binary, arch):
    p  = subprocess.Popen(["lipo", binary, "-verify_arch", arch], stdout=subprocess.PIPE, universal_newlines=True)
    output = p.communicate()[0]
    return p.returncode == 0

# Try to find the given library by searching in the typical locations
# Returns the full path to the library or None if the library is not found.
def lookup_library(file):
    found = None
    if re.search("^@rpath", file):
        file = re.sub("^@rpath", lc_rpath, file)
        if os.path.exists(file):
            if DEBUG: print("@rpath resolved: " + str(file))
            return file
    if not found:
        if re.search("\.app/", file):
            found = file
            if DEBUG: print("App found: " + str(found))
        elif re.search("@executable_path", file):
            abs = re.sub("^@executable_path", executable_path, file)
            if os.path.exists(abs): found = abs
            if DEBUG: print("Library in @executable_path found: " + str(found))
        elif re.search("\.framework/", file):
            found = os.path.join("/Library/Frameworks", file)
            if DEBUG: print("Framework found: " + str(found))
        else:
            for path in os.getenv("DYLD_LIBRARY_PATH").split(':'):
                abs = os.path.join(path, file)
                if os.path.exists(abs): found = abs
                if DEBUG: print("Library found: " + str(found))
    return found

# Returns a list of dependent libraries, excluding system libs
def find_dependencies(file):
    libs = []

    deps = get_libraries(file)
    for dep in deps:
        # print dep
        # Fail if libstc++ and libc++ was mixed
        global cxxlib
        match = re.search("lib(std)?c\+\+", dep)
        if match:
            if not cxxlib:
                cxxlib = match.group(0)
            else:
                if cxxlib != match.group(0):
                    print("Error: Mixing libc++ and libstdc++")
                    return None
        dep = re.sub(".*:$", "", dep) # Take away header line
        dep = re.sub("^\t", "", dep) # Remove initial tabs
        dep = re.sub(" \(.*\)$", "", dep) # Remove trailing parentheses
        if len(dep) > 0 and not re.search("/System/Library", dep) and not re.search("/usr/lib", dep):
            libs.append(dep)
    return libs

def validate_lib(lib):
    output, err = get_load_commands(lib)
    if not output:
        print('get_load_commands(): ' + err)
        return False

    # Check deployment target
    deploymenttarget = StrictVersion(get_deployment_target(output))
    if deploymenttarget > DEPLOYMENT_TARGET:
        print("Error: Unsupported deployment target " + m.group(2) + " found: " + lib)
        return False
    
    # This is a check for a weak symbols from a build made on 10.12 or newer sneaking into a build for an
    # earlier deployment target. The 'mkostemp' symbol tends to be introduced by fontconfig.
    output, err = get_global_symbols(lib)
    if not output:
        print('get_global_symbols(): ' + err)
        return False

    match = re.search("mkostemp", output)
    if match:
        print("Error: Reference to mkostemp() found - only supported on macOS 10.12->")
        return False

    if not verify_architecture(lib, ARCHITECTURE):
        print('Error: ' + ARCHITECTURE + ' architecture not supported: ' + lib)
        return False

    return True


def process_executable(executable):
    global executable_path, lc_rpath

    if DEBUG: print("Processing " + executable)
    executable_path = os.path.dirname(executable)
    
    # Find the Runpath search path (LC_RPATH)
    output, err = get_load_commands(executable)
    if not output:
        print('Error otool -l failed on main executable: ' + err)
        return False

    lc_rpath = get_rpath(output)
    if DEBUG: print('Runpath search path: ' + lc_rpath)

    # processed is a dict {libname : [parents]} - each parent is dependant on libname
    processed = {}
    pending = [executable]
    processed[executable] = []
    while len(pending) > 0:
        dep = pending.pop()
        if DEBUG: print("Evaluating " + dep)
        deps = find_dependencies(dep)
        assert(deps)
        for d in deps:
            absfile = lookup_library(d)
            if absfile == None:
                print("Not found: " + d)
                print("  ..required by " + str(processed[dep]))
                return False
                continue
            if not re.match(executable_path, absfile):
                print("Error: External dependency " + d)
                return False
            if absfile in processed:
                processed[absfile].append(dep)
            else: 
                processed[absfile] = [dep]
                if DEBUG: print("Pending: " + absfile)
                pending.append(absfile)

    for dep in processed:
       if DEBUG: print("--\nValidating: " + dep)
       if not validate_lib(dep):
           print("Could not validate " + dep)
           print("  ..required by " + str(processed[dep]))
           return False

    return True

if __name__ == '__main__':
    if len(sys.argv) != 2: usage()

    executable = sys.argv[1]

    error = not process_executable(executable)    

    sys.exit(error and 1 or 0)
