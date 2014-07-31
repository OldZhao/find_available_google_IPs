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
import IPy

github_url = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'
g_max_threading = 10
g_mutex = threading.Lock()
g_alive_list = []
g_source_list = []

# Normally the longer distance the more It spends time on connection.
g_area_weight = {'Bulgaria': 0,
                 'Egypt': 0,
                 'Hong Kong': 9,
                 'Iceland': 0,
                 'Indonesia': 0,
                 'Iraq': 0,
                 'Japan': 9,
                 'Kenya': 0,
                 'Korea': 8,
                 'Mauritius': 0,
                 'Netherlands': 0,
                 'Norway': 0,
                 'Philippines': 0,
                 'Russia': 0,
                 'Saudi Arabia': 0,
                 'Serbia': 0,
                 'Singapore': 9,
                 'Slovakia': 0,
                 'Taiwan': 9,
                 'USA': 8,
                 'Thailand': 7}


def get_ips_from_github():
    """Download the IP-list-file from github.com,
    and write to file github.ip

    output format example:
        are=Hong Kong
        1.2.3.4
        5.6.7.8

    Args:
        None

    Returns:
        A dictionary with key(the area name) and value(IP list),
        If failed, return None
    """
    print 'downloading ip-file from github.com ...',
    urllib.urlretrieve(github_url, 'ips.md')
    print ' [ok]'

    print 'analyzing IP file ...'
    re_area = re.compile('>\w+\s?\w+<', re.I)
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
        # write to file github.ip
        path = os.path.join(os.getcwd(), 'github.ip')
        f = open(path, 'w')
        total = 0
        for k in dic:
            total += len(dic[k])
            f.writelines('area='+k+'\n')
            ips = '\n'.join(dic[k])+'\n\n'
            f.writelines(ips)
        f.close()
        print 'Success, get total IPs = %s , save to file:%s' % (total, path)
        return dic
    except Exception, data:
        # pass
        print '%s : %s' % (Exception, data)
    finally:
        f.close()


def nslookup():
    """-> Query Google's SPF record to retrieve the range of IP address
    """
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
    arr = [x.split(':')[1] for x in arr]
    print '-> Receive IP range:'
    print arr
    ip_list = []
    total = 0
    for x in arr:
        ips = IPy.IP(x)
        f = [str(i) for i in ips]
        total += len(f)
        ip_list.extend(f)

    print '-> Change to IP list:'
    print '-> Total IPs %s' % total
    # Write to file
    f = open(os.path.join(os.getcwd(), 'nslookup.ip'), 'w')
    try:
        f.writelines('\n'.join(ip_list))
        print '-> Save IP list to file : %s' % 'nslookup.ip'
    except Exception, e:
        print e
    finally:
        f.close()
    return ip_list


def sort_ip_list(github_ip_list, nslook_ip_list):
    """Sort the IP list by area-weight
    """
    for k in g_area_weight.keys():
        if g_area_weight[k] <= 7:
            del github_ip_list[k]

    del g_source_list[:]
    for i in range(8, 10)[::-1]:
        for k in g_area_weight.keys():
            if g_area_weight[k] == i:
                g_source_list.extend(github_ip_list[k])
                break
    g_source_list.extend(nslook_ip_list)
    print '-> Sort IP list finished!'


def th_port_detect():
    """Try to connect the host by https.
    """
    while True:
        ip = get_one_ip(g_source_list)
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
                g_alive_list.append(ip)
                # Save available IPs to file, in case program is aborted by
                # user in anytime
                if len(g_alive_list) >= 3:
                    break
                    #f = open('alive.ip', 'a')
                    #try:
                    #    g_mutex.acquire()
                    #    f.writelines('\n'.join(alive_list))
                    #    del g_alive_list[:]
                    #except:
                    #    pass
                    #finally:
                    #    f.close()
                    #    g_mutex.release()
            else:
                print ' Timeout '
        except:
            print ' Failed'


def get_one_ip(ip_list):
    if len(ip_list) == 0:
        return None
    else:
        g_mutex.acquire()
        ip = ip_list.pop(0)
        g_mutex.release()
        return ip


def detect_alive_ip():
    """ Detect alive IP
    """
    del g_alive_list[:]
    if os.path.isfile('alive.ip'):
        os.remove('alive.ip')

    th_pool = []
    for i in range(g_max_threading):
        th = threading.Thread(target=th_port_detect)
        th_pool.append(th)
        th.start()

    for i in range(g_max_threading):
        threading.Thread.join(th_pool[i])

    # Save available IPs to file
    f = open('alive.ip', 'a')
    ips = '\n'.join(g_alive_list)
    f.writelines(ips)
    f.close()

    print '-> Detecting alive IP FINISHED! '


git = get_ips_from_github()
spf = nslookup()
sort_ip_list(git, spf)
detect_alive_ip()
