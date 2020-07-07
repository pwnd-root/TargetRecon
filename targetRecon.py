import argparse
import os
import sys
from support.target import TargetService
from support.scans import openPortsScan
from support.scans import scriptsScan

def getArgs ():

    parser = argparse.ArgumentParser (description = "\033[31mTarget Reconnaissance\033[0m")
    parser.add_argument ('target', action = 'store', type = str, help = 'Target IP address')
    parser.add_argument ('-o', '--open', action = 'store_true', help = 'Report open ports and stop further scanning',
                         dest = 'openScan')
    parser.add_argument ('-s', '--script', action = 'store_true', help = 'Perform --script=default,vuln and stop',
                         dest = 'script')

    args = parser.parse_args ()

    if args.openScan and args.script:
        parser.error ('\033[31m[!] --open and --script cannot be clubbed together. Specify either.\033[0m')
        sys.exit (1)

    return args


def main ():

    args = getArgs ()
    target = args.target
    openScan = args.openScan
    script = args.script
    log = os.path.join (os.getcwd (), 'recon.log')
    openPorts = openPortsScan (target, log)
    if openPorts:
        if not openScan:
            openPorts = scriptsScan (target, openPorts, log)
            print ('\033[34mSummary \033[0m')
            for openPort in openPorts:
                print ('\033[32m\t' + openPort.port + '\033[31m\t' + openPort.service + '\033[32m\t' + openPort.product
                       + ' ' + openPort.version + '\033[0m')
                if openPort.vuln:
                    print ('\033[31m\t\tVulnerabilites\033[32m')
                    print ('\t\t\t' + openPort.vuln, sep = ', ')
                else:
                    print ('\033[31m\t\tNo vuln found\033[0m')

            """More modules planned"""
    else:
        print ("\033[31m\tHost down or All ports are filtered")

    return 0


if __name__ == '__main__':
    main ()