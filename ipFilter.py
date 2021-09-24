#!/usr/bin/python
# -*- coding: UTF-8 -*-
# **********************************************************
# * Author        : J14nk3r
# * Create time   : 2021-09-23 14:00
# * Last modified : 2021-09-23 14:00
# * Filename      : ipFilter.py
# * Description   : Filter out source IP related information from the log
# **********************************************************

import os
import re
import argparse
import json
import requests

def IP_Filter(raw_log):
    #Filter out the source IP from the raw log
    IP_list = {}
    with open(raw_log, "r") as f:
        for l in f:
            ip = re.findall(r'\d+.\d+.\d+.\d+', l.strip(' '))
            if ip[0] in IP_list:
                IP_list[ip[0]] += 1
            else:
                IP_list[ip[0]] = 1
    tmp = sorted(IP_list.items(), key = lambda x:x[1], reverse=True)
    return tmp

def Check_Threshold(IP_idx, target):
    #Filter out IPs that exceed the threshold
    Potential_IP = []
    for IP_info in IP_idx:
        if IP_info[1] >= target:
            Potential_IP.append(IP_info[0])
        else:
            break
    return Potential_IP

def Check_country(IP_idx):
    #Determine where the source IP belongs, and filter out the external network IP
    external_IP = {}
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko','Accept': 'text/html, application/xhtml+xml, image/jxr, */*','Accept-Language': 'zh-CN','Connection': 'close'}
    for IP_info in IP_idx:
        URL = 'http://ip-api.com/json/'+IP_info[0]+'?lang=zh-CN'
        r = requests.get(URL, timeout=3,headers=headers)
        IP_data = r.json()
        if IP_data[u'status'] == 'success':
            country = IP_data[u'country']
            provice = IP_data[u'regionName']
            city = IP_data[u'city']
            if country != '中国':
                external_IP[IP_data[0]] = country
    return external_IP

def Contruct_output(opath, IP_idx, Potential_attack_IP, foreigh_ip):
    #Save the filter results to the local
    f = open(opath, 'w')
    f.writelines('The log extraction results of the file are as follows:\n')
    for IP_info in IP_idx:
        f.writelines(IP_info[0] + ' : ' + IP_info[1] + '\n')
    f.writelines('\n')

    f.writelines('The  Potential attack IP of the file are as follow:\n')
    for IP_info in Potential_attack_IP:
        f.writelines(IP_info)
    f.writelines('\n')

    f.writelines('The external IP is as follows\n')
    for IP_info in foreigh_ip:
        f.writelines(IP_info +'source:'+foreigh_ip[IP_info])
    f.writelines('\n')
    f.close()

def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("-raw_log", help="Please input the raw log file to be parsed", type=str)
    parse.add_argument("-output", help="Please set the output file name", type=str)
    parse.add_argument("-Threshold", help="Please set the threshold to filter number of IPs", type=int)
    arg = parse.parse_args()
    raw_log = arg.raw_log
    raw_log = os.path.abspath(raw_log)
    Threshold = arg.Threshold
    opath = arg.output
    opath = os.path.abspath(opath)

    #Filter IP, the data type is set
    IP_idx = IP_Filter(raw_log)

    #Extract IP addresses that exceed the threshold, the data type is list
    Potential_attack_IP = Check_Threshold(IP_idx, Threshold)

    #Checking whether it is a foreign IP, this data type is dictionary 
    foreigh_ip = Check_country(IP_idx)

    #Encapsulate the data into a txt file
    Contruct_output(opath, IP_idx, Potential_attack_IP, foreigh_ip)

if __name__ == "__main__":
    main()