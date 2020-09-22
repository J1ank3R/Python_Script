import paramiko
import socket

def connect_demo(IP,user,old_password,new_password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=IP, port=22, username=user, password=old_password,timeout=5)
        command = "passwd %s" %(user)
        stdin, stdout, stderr = ssh.exec_command(command)
        stdin.write(old_password + '\n')
        stdin.write(new_password + '\n' + new_password + '\n')
        out, err = stdout.read(), stderr.read()
        successful = 'password updated successfully'
        if successful in str(err):
            print(IP+" :password has been changed")
        else:
            print(str(err))
        ssh.close()
    except paramiko.ssh_exception.AuthenticationException as e:
        print(IP + ' ' + "dont need change")
    except socket.timeout as e:
        print(IP+"connect timeout")


IPaddress = ['172.16.0.7','172.16.0.202','172.16.0.100','172.16.0.140']
for i in range(len(IPaddress)):   
    IP = IPaddress[i]  
    connect_demo(IP,"ubuntu","openstack","chtMBFTQx8")
# def main():
#     IPaddress = ['172.16.0.7','172.16.0.202','172.16.0.100','172.16.0.140']
#     for i in range(len(IPaddress)):
#         IP = IPaddress[i]
#         user = "ubuntu"
#         old_password = "openstack"
#         new_password = ""
#         connect_demo(IP,user,old_password,new_password)
# if __name__ == "__main__":
#     main()

