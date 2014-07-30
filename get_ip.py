#!/usr/bin/env python
# -*- coding:utf-8 -*-
# search the public IPs from Internet.

import urllib
import os
import os.path
import re
import httplib
import threading
import subprocess

github_url = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'
max_threading = 10
g_mutex = threading.Lock()
alive_list = []
source_list = []
available_ip_file_name = 'available.ip.list'


def get_ips():
    print 'downloading ip-file from github.com ...',
    urllib.urlretrieve(github_url, 'ips.md')
    print ' [ok]'

    print 'analyzing IP file ...'
    re_area = re.compile('>\w+<', re.I)
    re_ip = re.compile('\d+.\d+.\d+.\d+')
    dic = {}
    path = os.path.join(os.getcwd(), 'ips.md')
    f = open(path, "r")
    try:
        key = ''
        lst = list()
        for line in f:
            if 'th' in line:
                # add to dictionary
                if len(key) > 0 and len(lst) > 0:
                    print 'area = %s, total IPs = %s' % (key, len(lst))
                    # merge the IP list for existed-area-key in dictionay
                    if key in dic.keys():
                        lst.extend(dic[key])
                    dic[key] = lst
                    key = ''
                    lst = list()
                match = re_area.search(line)
                if match:
                    key = match.group(0)[1:-1].strip()
            elif 'td' in line:
                match = re_ip.search(line)
                if match:
                    lst.append(match.group(0))
        f.close()
        os.remove(path)
        # write to file ip.list
        f = open('ip.list', 'w')
        total = 0
        for k in dic:
            total += len(dic[k])
            f.writelines('area='+k+'\n')
            ips = '\n'.join(dic[k])+'\n\n'
            f.writelines(ips)
        f.close()
        print 'Success, get total IPs = %s ' % total
        return dic
    except Exception, data:
        # pass
        print '%s : %s' % (Exception, data)
    finally:
        f.close()


def sort_area():
    arr = area_weight.split('\n')
    lst = list()
    for a in arr:
        s = a.replace(' ', '').split('=')
        if len(s) == 2:
            s[1] = int(s[1])
            lst.append(s)
        else:
            s.append(0)
            lst.append(s)
    lst.sort(key=lambda lst: lst[1], reverse=True)
    # print lst
    return lst


def port_detect():
    while True:
        ip = get_one_ip()
        if ip is None:
            break

        try:
            print 'Connecting %s ...' % ip,
            c = httplib.HTTPSConnection(ip, timeout=3)
            c.request("GET", "/")
            response = c.getresponse()
            result = str(response.status)+' '+response.reason
            if '200 OK' in result:
                print ' OK '
                alive_list.append(ip)
                # Save available IPs to file, in case program is aborted by
                # user in anytime
                if len(alive_list) >= 3:
                    f = open(available_ip_file_name, 'a')
                    try:
                        g_mutex.acquire()
                        f.writelines('\n'.join(alive_list))
                        del alive_list[:]
                    except:
                        pass
                    finally:
                        f.close()
                        g_mutex.release()
            else:
                print ' Timeout '
        except:
            print ' Failed'


def get_one_ip():
    if len(source_list) == 0:
        return None
    else:
        g_mutex.acquire()
        ip = source_list.pop(0)
        g_mutex.release()
        return ip


def detecting(dic_ips, area_sorted_list):
    # merge all IPs to a list with sorted
    for item in area_sorted_list:
        if item in dic_ips.keys():
            source_list.extend(dic_ips[item])
            del dic_ips[iptem]
    for item in dic_ips.keys():
        source_list.extend(dic_ips[item])
    print source_list[0:20]

    path = os.path.join(os.getcwd(), available_ip_file_name)
    if os.path.isfile(path):
        os.remove(path)

    th_pool = []
    for i in range(max_threading):
        th = threading.Thread(target=port_detect)
        th_pool.append(th)
        th.start()

    for i in range(max_threading):
        threading.Thread.join(th_pool[i])

    # Save available IPs to file
    f = open(path, 'a')
    ips = '\n'.join(alive_list)
    f.writelines(ips)
    f.close()

    print 'done!'


def nslookup():
    # https://support.google.com/a/answer/60764?hl=zh-Hans
    # nslookup -q=TXT _spf.google.com 8.8.8.8
    # nslookup -q=TXT _netblocks.google.com 8.8.8.8
    # nslookup -q=TXT _netblocks2.google.com 8.8.8.8
    # nslookup -q=TXT _netblocks3.google.com 8.8.8.8

    print "-> Query Google's SPF record to retrieve the range of IP address..."
    # Try 5 times to retrieve the SPF records
    spf = 'nslookup -q=TXT _spf.google.com 8.8.8.8'
    domain = []
    for i in range(5):
        p = subprocess.Popen(
            spf, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,   stderr=subprocess.PIPE, shell=True)
        out = p.stdout.read()
        # print out
        res = re.findall(r'~all', out)
        if not res:
            print '-> Timeout(%s),try again...' % i
            continue
        else:
            s = re.search(r'".+"', out).group()
            arr = s.split(' ')[1:-1]
            for txt in arr:
                domain.append(txt.split(':')[1])
            print "-> Recieve the list of the domains included in Google's SPF record:"
            print domain
            break
    if len(domain) == 0:
        print '-> Damn it, nslookup timeout. We get nothing!'
        return None
    print '-> Query IP range...'
    # get IP range
    res = ''
    for d in domain:
        cmd = 'nslookup -q=TXT %s 8.8.8.8' % d
        for j in range(5):
            p = subprocess.Popen(
                cmd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,   stderr=subprocess.PIPE, shell=True)
            out = p.stdout.read()
            if '~all' not in out:
                continue
            if 'ip4' in out:
                res = re.search(r'".+"', out).group()
                break
            else:
                break
        if len(res) > 0:
            break

    if len(res) == 0:
        print '-> Damn it, nslookup timeout. We get nothing!'
        return None

    arr = res.split(' ')[1:-1]
    arr2 = []
    for txt in arr:
        arr2.append(txt.split(':')[1])
    del arr[:]
    ip_list = []
    print '-> Receive IP range:'
    print arr2
    for txt in arr2:
        arr = re.search(r'\d+/\d+', txt).group().split('/')
        if arr[0] == '0':
            arr[0] = 1
        arr[1] = int(arr[1])+1
        ip3 = re.search(r'\d+\.\d+\.\d+\.', txt).group()
        for ip4 in range(arr[0], arr[1]):
            ip_list.append(ip3+str(ip4))
    print '-> Change to IP list:'
    print ip_list
    # Write to file
    f = open(os.path.join(os.getcwd(), 'nslookup.ip'), 'w')
    try:
        f.writelines('\n'.join(ip_list))
    except:
        pass
    finally:
        f.close()


nslookup()

# area_weight = '''Korea=8
# Singapore=8
# Egypt=5
# Iceland=5
# Philippines=7
# Indonesia=7
# Serbia=5
# Mauritius=5
# Netherlands
# Slovakia=5
# Kenya=5
# Japan=9
# Taiwan=8
# Iraq=5
# Norway=5
# Russia=5
# Thailand=7
# Bulgaria=5'''
