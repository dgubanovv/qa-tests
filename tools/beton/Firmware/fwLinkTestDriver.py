# !2.1.1. Set link speed to "Autonegotiation" in driver on local machine (DUT), and switch through all possible options on remote machine: after switching to 
# !       new speed, link should be up, rate should be as requested, and ping passing
# !       
# !
# !2.1.2. Same as 2.1.1, but do disable/enable for every speed on both local and remote machine
# !       
# !
# !2.1.3. Set link speed to "Autonegotiation" in driver on remote machine, and switch through all possible options on lockal machine: after switching to new 
# !       speed, link should be up, rate should be as requested, and ping passing
# !       
# !
# !2.1.4. Same as 2.1.3, but do disable/enable for every speed on both local and remote machine
# !       
import subprocess
import re
import testresult
import sys
from time import sleep


###################################################
LOCAL_IP = '192.168.0.1' # address for peer-to-peer connection
LOCAL_IP_TO_ACCESS = '172.30.1.5'
REMOTE_USER = 'aquantia'
REMOTE_PWD = 'aqu$3r'
REMOTE_IP = '192.168.0.1' # address for peer-to-peer connection
REMOTE_IP_TO_ACCESS = '172.30.1.4'
REMOTE_SN = 'AquantiaNDMP' #'ixgbt'
LOCAL_SN = 'AquantiaNDMP'

final_report = []
links = {'100M':'100000000', '1G':'1000000000', '2.5G':'2500000000', '5G':'5000000000', } # '10G':'10000000000'}
# links = {'100M':'100000000', '1G':'1000000000'}
###################################################

def get_nic_id(service_name, host_type):
    if host_type.lower() == 'remote':
        cmd = "wmic /node:%s /user:%s /password:%s nic where (ServiceName=\"%s\" and NetEnabled=True) get index" %(REMOTE_IP_TO_ACCESS, REMOTE_USER, REMOTE_PWD, service_name)
    else:   
        cmd = "wmic nic where (ServiceName=\"%s\" and NetEnabled=True) get index" %(service_name)
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if 'No Instance(s) Available' in res:
        raise Exception("No access to remote NIC")    
    return re.findall('\d+', res)[0]

    
def eth_local_action(index, action):
    cmd = "wmic path win32_networkadapter where index=%s call %s" %(index, action.lower())
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if'ReturnValue = 0' not in res:
        raise Exception("Error while action executing on local")
    
def eth_local_get_speed(index):
    # cmd = "wmic nic where index=%s get speed | find \"%s\" " %(index, speed) # speed format is "10000000000"
    cmd = "wmic nic where index=%s get speed" %(index)
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if len(re.findall('\d+', res))>0:
        return re.findall('\d+', res)[0]
    return None
    
def eth_local_set_speed(index, speed):
    speed = ("32" if speed == "100M" else "16" if speed == "1G" else "8" if speed == "2.5G" else "2" if speed == "5G" else "1" if speed == "10G" else "65535")
    pref = ("000" if len(str(index)) == 1 else "00" if len(str(index)) == 2 else "0")
    cmd = r"reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\%s /v LinkSpeed /f /t reg_sz /d %s" %(pref+str(index), speed)
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if 'successfully' not in res:
        raise Exception("Error while set speed executing on local")
    
    
def eth_remote_action(remote_index, remote_action):    
    cmd = "wmic /node:%s /user:%s /password:%s path win32_networkadapter where index=%s call %s" %(REMOTE_IP_TO_ACCESS, REMOTE_USER, REMOTE_PWD, remote_index, remote_action.lower())
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if'ReturnValue = 0' not in res:
        raise Exception("Error while action executing on remote")
    
def eth_remote_get_speed(remote_index):    
    cmd = "wmic /node:%s /user:%s /password:%s nic where index=%s get speed" %(REMOTE_IP_TO_ACCESS, REMOTE_USER, REMOTE_PWD, remote_index)
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if len(re.findall('\d+', res))>0:
        return re.findall('\d+', res)[0]
    return None

def eth_remote_set_speed(index, speed):
    pref = ("000" if len(str(index)) == 1 else "00" if len(str(index)) == 2 else "0")
    
    if REMOTE_SN == 'ixgbt':
        speed = ("4" if speed == "100M" else "6" if speed == "1G" else "7" if speed == "10G" else "0")
        reg = r"reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\%s /v *SpeedDuplex /f /t reg_sz /d %s" %(pref+str(index), speed)
    elif REMOTE_SN == 'AquantiaNDMP':
        speed = ("32" if speed == "100M" else "16" if speed == "1G" else "8" if speed == "2.5G" else "2" if speed == "5G" else "1" if speed == "10G" else "65535")
        reg = r"reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\%s /v LinkSpeed /f /t reg_sz /d %s" %(pref+str(index), speed)
    else:
        raise NotImplementedError("No implemented for such card type")
    
    cmd = "wmic /node:%s /user:%s /password:%s process call create " %(REMOTE_IP_TO_ACCESS, REMOTE_USER, REMOTE_PWD) 
    cmd = cmd + '\"%s \"' %(reg)
    res = subprocess.check_output(cmd, shell=True).rstrip()
    if'ReturnValue = 0' not in res:
        raise Exception("Error while set speed executing on remote")

def ping(ip):
    cmd = "ping -n 2 %s" %(ip)
    res = subprocess.check_output(cmd, shell=True).rstrip()
    return('Destination host unreachable' not in res)

def do_exit():
    testresult.show_test_result(final_report)
    sys.exit()
        
######################################################################################################    
if __name__ == "__main__":
    if not ping(REMOTE_IP):
        raise Exception("Remote host is N/A")
        
    
    remote_nic_id = get_nic_id(REMOTE_SN, 'remote')
    local_nic_id  = get_nic_id(LOCAL_SN, 'local')
    # remote_nic_id = 7
    # local_nic_id = 16
    print ("NIC id: local = %s, remote = %s") %(local_nic_id, remote_nic_id)
        
    autoNegHosts = ['local', 'remote']
    for autoNegHost in autoNegHosts:
        if autoNegHost == 'local':
            print ("Set Autonegotiation on local")
            eth_local_set_speed(local_nic_id, 'Auto')
            eth_local_action(local_nic_id, 'disable')
            eth_local_action(local_nic_id, 'enable')
            sleep(15)    

            for link in links.keys():
                print("Setting speed %s on remote") %(link)
                eth_remote_set_speed(remote_nic_id, link)
                eth_remote_action(remote_nic_id, 'disable')
                eth_local_action(local_nic_id, 'disable')
                sleep(3)
                eth_remote_action(remote_nic_id, 'enable')
                eth_local_action(local_nic_id, 'enable')
                sleep(15)
                
                actual_speed = eth_local_get_speed(local_nic_id)
                if actual_speed != links[link]:
                    print("Wrong speed: actual = %s, expected = %s ") %(actual_speed, links[link])
                    final_report += [('(0) Wrong speed detected. Expected speeed:  %s') %(link)]
                    do_exit()
                if not ping(REMOTE_IP):
                    print("Remote is N/A")
                    final_report += [('(1) Remote host is N/A, speed = %s') %(link)]
                    do_exit()
                
                eth_remote_action(remote_nic_id, 'disable')
                eth_local_action(local_nic_id, 'disable')
                sleep(3)
                eth_remote_action(remote_nic_id, 'enable')
                eth_local_action(local_nic_id, 'enable')
                sleep(15)
                
                actual_speed_2 = eth_local_get_speed(local_nic_id)
                if actual_speed_2 != links[link]:
                    print("Wrong speed: actual = %s, expected = %s ") %(actual_speed_2, links[link])
                    final_report += [('(2) Wrong speed detected. Expected speeed:  %s') %(link)]
                    do_exit()
                
        else:
            print ("Set Autonegotiation on remote")
            eth_remote_set_speed(remote_nic_id, 'Auto')
            eth_remote_action(remote_nic_id, 'disable')
            eth_remote_action(remote_nic_id, 'enable')
            sleep(15)
        
            for link in links.keys():
                print("Setting speed %s on local") %(link)
                eth_local_set_speed(local_nic_id, link)
                eth_local_action(local_nic_id, 'disable')
                eth_remote_action(remote_nic_id, 'disable')
                sleep(3)
                eth_remote_action(remote_nic_id, 'enable')
                eth_local_action(local_nic_id, 'enable')
                sleep(15)
                
                actual_speed = eth_remote_get_speed(remote_nic_id)
                if actual_speed != links[link]:
                    print("Wrong speed: actual = %s, expected = %s ") %(actual_speed, links[link])
                    final_report += [('(3) Wrong speed detected. Expected speeed:  %s') %(link)]
                    do_exit()
                if not ping(REMOTE_IP):
                    print("Remote is N/A")
                    final_report += [('(4) Remote host is N/A, speed = %s') %(link)]
                    do_exit()
                
                eth_local_action(local_nic_id, 'disable')
                eth_remote_action(remote_nic_id, 'disable')
                sleep(3)
                eth_remote_action(remote_nic_id, 'enable')
                eth_local_action(local_nic_id, 'enable')
                sleep(15)
                
                actual_speed_2 = eth_remote_get_speed(remote_nic_id)
                if actual_speed_2 != links[link]:
                    print("Wrong speed: actual = %s, expected = %s ") %(actual_speed_2, links[link])
                    final_report += [('(5) Wrong speed detected. Expected speeed:  %s') %(link)]
                    do_exit()
                    
    # Test Autoneg to Autoneg
    eth_local_set_speed(local_nic_id, 'Auto')
    eth_remote_set_speed(remote_nic_id, 'Auto')
    eth_local_action(local_nic_id, 'disable')
    eth_remote_action(remote_nic_id, 'disable')
    eth_remote_action(remote_nic_id, 'enable')
    eth_local_action(local_nic_id, 'enable')
    sleep(15)
    
    actual_speed_remote = eth_remote_get_speed(remote_nic_id)
    actual_speed_DUT = eth_local_get_speed(local_nic_id)
    
    if not ping(REMOTE_IP):
        print("Remote is N/A")
        final_report += [('(6) Remote host is N/A, speed = %s') %(link)]
    
    if actual_speed_remote != actual_speed_DUT:
        print("Wrong speed: actual speed on remote = %s, actual speed on DUT = %s ") %(actual_speed_remote, actual_speed_DUT)
        final_report += ['(7) Wrong speed for Auto to Auto']
    
    # Show test result        
    testresult.show_test_result(final_report)
