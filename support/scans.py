import os
import subprocess
import xml.etree.ElementTree as ET
from support.target import TargetService

xml = os.getcwd() + '/NmapXml'
if not os.path.isdir(xml):
    os.makedirs (xml)


def openPortsScan (target, log):
    print ('\033[34m[+] Open Ports Scan\033[0m')
    openPorts = []
    scanOp = xml + '/' + target + '_openPorts.xml'
    scanResult = subprocess.run (['nmap', '-Pn', '-T4', '--min-rate=1000', target, '-oX', scanOp],
                                 stdout = subprocess.PIPE, universal_newlines = True)
    with open (log, 'w') as l:
        l.write ('\n'.join ( scanResult.stdout.splitlines() ) )

    root = ET.parse (scanOp).getroot ()
    for host in root.findall ('host'):
        portElements = host.findall ('ports')
        for port in portElements [0].findall ('port'):
            # Identifying open ports
            if (port.findall ('state') [0].attrib ['state']) == 'open':
                openPort = port.attrib ['portid']
                # Service name
                service = port.findall ('service') [0].attrib ['name']
                print ('\033[32m\t' + openPort + '\033[31m\t' + service + '\033[0m')
                a = TargetService (openPort, service)
                openPorts.append (a)

    return openPorts


def scriptsScan (target, openPorts, log):
    print ('\033[34m[+] Scripts Scan\033[0m')

    for openPort in openPorts:
        port = openPort.port
        service = openPort.service
        vulns = []
        scanOp = xml + '/' + target + '_' + service + '_scriptScan.xml'
        print ('\t\t\033[31m nmap -sV -A --script=default,vuln -p ' + port + ' ' + target + '\033[0m')
        scanResult = subprocess.run (['nmap', '-Pn', '-sV', '-A', '--script=default,vuln', '-p', port, target, '-oX', scanOp],
                                     stdout = subprocess.PIPE, universal_newlines = True)
        with open (log, 'a') as l:
            l.write ( '\n'.join (scanResult.stdout.splitlines()) )
            
        print ('\033[33m')
        print ( '\n'.join (scanResult.stdout.splitlines()) )
        print ('\033[0m')

        root = ET.parse (scanOp).getroot ()
        for host in root.findall ('host'):
            portElements = host.findall ('ports')
            for port in portElements [0].findall ('port'):
                # Identifying open ports
                if (port.findall ('state') [0].attrib ['state']) == 'open':
                    portid = port.attrib ['portid']
                    # Service name
                    portSrv = port.findall ('service') [0].attrib ['name']
                    try:
                        product = port.findall ('service') [0].attrib ['product']
                        try:
                            version = port.findall ('service') [0].attrib ['version']
                        except:
                            version = 'N/A'
                    except:
                        product = 'N/A'
                        version = 'N/A'
            try:
                hostScript = host.findall ('hostscript')
                for script in hostScript [0].findall ('script'):
                    if 'VULNERABLE' in script.attrib ['output']:
                        vulns.append (script.attrib ['id'])
                        # print ('\t\t\033[32mVULNERABLE' + '\033[0m ==>\t\033[31m' + script.attrib ['id'] + '\033[0m')
            except:
                vulns = []

            openPort.product = product
            openPort.version = version
            openPort.vuln = vulns

            # print ('\033[35m' + openPort.port + openPort.service + openPort.product + openPort.version)

    return openPorts
