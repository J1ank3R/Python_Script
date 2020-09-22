import nmap
import socket
import wmi


def Selectgetway(HostIP):
    IP = HostIP
    nm = nmap.PortScanner()
    i = 1
    while i < 3:
        newIP1 = IP[:-2] + str(int(ip[-2:]) + i)
        newIP2 = IP[:-2] + str(int(ip[-2:]) - i)
        try:
            nm.scan(newIP1, '2222')
            para1 = nm[newIP1].tcp(2222)
            if para1['state'] == 'open':
                return newIP1
            else:
                try:
                    nm.scan(newIP2, '2222')
                    para2 = nm[newIP2].tcp(2222)
                    if para2['state'] == 'open':
                        return newIP2
                    else:
                        i += 1
                except:
                    i += 1
        except:
            try:
                nm.scan(newIP2, '2222')
                para2 = nm[newIP2].tcp(2222)
                if para2['state'] == 'open':
                    return newIP2
                else:
                    i += 1
            except:
                i += 1


#    return IP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('192.168.111.139', 1111))
ip = s.getsockname()[0]
#print("hostIP=",ip)
Getway = Selectgetway(ip)
#print(Getway)
wmiService = wmi.WMI()
colNicConfigs = wmiService.Win32_NetworkAdapterConfiguration(IPEnabled=True)
objNicConfig = colNicConfigs[0]

VPNGetways = [Getway]
GetwayCostMetrics = [1]
returnValue = objNicConfig.SetGatways(DefaultIPGateway=VPNGetways,
                                      GatewayCostMetric=GetwayCostMetrics)
