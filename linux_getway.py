import nmap
import socket
import os
#print(ip[:-2])
#print(ip[-2:])
#print(ip)
#ip1 = ip[:-2] + str(int(ip[-2:])+1)
#print(ip1)
def Selectgetway(HostIP):
    IP = HostIP
    nm = nmap.PortScanner()
    i = 1
    while i < 3:
        newIP1 = IP[:-2] + str(int(ip[-2:])+i)
        newIP2 = IP[:-2] + str(int(ip[-2:])-i)
        try:
            nm.scan(newIP1,'22')
            para1=nm[newIP1].tcp(22)
            if para1['state']=='open':
                return newIP1
            else:
                try:
                    nm.scan(newIP2,'22')
                    para2=nm[newIP2].tcp(22)
                    if para2['state']=='open':
                        return newIP2
                    else:
                        i+=1
                except:
                    i+=1
        except:
            try:
                nm.scan(newIP2,'22')
                para2=nm[newIP2].tcp(22)
                if para2['state']=='open':
                    return newIP2
                else:
                    i+=1
            except:
                i+=1
#    nm.scan(IP,'22')
#    para=nm[IP].tcp(22)
#    if para['state']=='open':
        return IP
#nm = nmap.PortScanner()
#nm.scan('192.168.111.189','22')
#para = nm['192.168.111.189'].tcp(22)
#print(nm[ip].tcp(22)['state'])
s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.connect(('192.168.111.139',1111))
ip = s.getsockname()[0]
Getway = Selectgetway(ip)
#print(Getway)
os.system('route add default gw %s dev ens33'%Getway)
#nm=nmap.PortScanner()

