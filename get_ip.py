#!/usr/bin/env python
# -*- coding:utf-8 -*-

# search Google's IPs from the Internet.

import urllib
import os
import os.path
import re
import httplib
import threading
import subprocess
import IPy


class GetIP(object):

    """Get IP from github and GOOGLE SPF
    """
    __g_max_threading = 10
    __g_source_list = []
    __g_alive_list = []

    __github_url = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'

    # Normally the longer distance the more It spends time on connection.
    __g_area_weight = {'Bulgaria': 0,
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

    def __get_iplist_from_github(self, url=self.__github_url):
        """Download the IP-list-file from github.com,
        and write to file github.ip

        output format example:
            are=Hong Kong
            1.2.3.4
            5.6.7.8

        Args:
            url, default='https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'

        Returns:
            A dictionary with key(the area name) and value(IP list),
            If failed, return None
        """
        if not url:
            url = self.__github_url
        print '-> Downloading file from github.com...',
        urllib.urlretrieve(url, 'github.ips.source')
        print ' [ok]'

        print '-> Analyzing file...'
        re_area = re.compile('>\w+\s?\w+<', re.I)
        re_ip = re.compile('\d+.\d+.\d+.\d+')
        dic = {}
        f = open('github.ips.source', 'r')
        key = ''
        lst = list()
        for line in f:
            if 'th' in line:
                # add to dictionary
                if len(key) > 0 and len(lst) > 0:
                    print '   area = %s, %s IPs' % (key, len(lst))
                    # merge the IP list for existed-area-key in dictionay
                    if key in dic:
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
        os.remove('github.ips.source')
        # write to file github.ip
        f = open('github.ip', 'w')
        total = 0
        for k in dic:
            total += len(dic[k])
            f.writelines('area=' + k + '\n')
            ips = '\n'.join(dic[k]) + '\n\n'
            f.writelines(ips)
        f.close()
        print '-> Done! Get %s IPs from Github, save to file [github.ip]' % total
        return dic

    def __get_iplist_by_nslookup(self):
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
                print '-> Timeout,try again (%s) ...' % i
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
            print '-> Damn it~ We get nothing!'
            return None
        print '-> Query IP range...'
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
            print '-> Damn it~ We get nothing!'
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
        print '-> Get %s IPs' % total
        # Write to file
        f = open('nslookup.ip', 'w')
        try:
            f.writelines('\n'.join(ip_list))
            print '-> Save IP list to file [nslookup.ip]'
        except IOError:
            print 'Error : save to file error.'
        finally:
            f.close()
        return ip_list

    def __sort_ip_list(self, github_ip_list, nslook_ip_list):
        """Sort the IP list by area-weight
        """
        for k in self.__g_area_weight:
            if __g_area_weight[k] <= 7:
                del github_ip_list[k]

        print 'git ip left ' + len(github_ip_list)

        del __g_source_list[:]
        for i in range(8, 10)[::-1]:
            for k in __g_area_weight:
                if __g_area_weight[k] == i:
                    __g_source_list.extend(github_ip_list[k])
                    break
        print 'git ip left ,g_source_list ' + len(__g_source_list)
        __g_source_list.extend(nslook_ip_list)
        print ' all g_source_list length ' + len(__g_source_list)
        print '-> Sort IP list finished!'

    def __th_port_detect(self):
        """Try to connect the host by https.
        """
        while True:
            ip = get_one_ip(__g_source_list)
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
                    __g_alive_list.append(ip)
                    # Save available IPs to file, in case program is aborted by
                    # user in anytime
                    if len(__g_alive_list) >= 3:
                        __g_mutex.acquire()
                        f = open('alive.ip', 'a')
                            try:
                                f.writelines('\n'.join(__g_alive_list))
                                del __g_alive_list[:]
                            except:
                                pass
                            finally:
                                f.close()
                                g_mutex.release()
                else:
                    print response.status
            except:
                print ' Failed'

    def __get_one_ip(self, ip_list):
        if len(ip_list) == 0:
            return None
        else:
            g_mutex.acquire()
            ip = ip_list.pop(0)
            g_mutex.release()
            return ip

    def __detect_alive_ip(self):
        """ Detect alive IP
        """
        del __g_alive_list[:]
        if os.path.isfile('alive.ip'):
            os.remove('alive.ip')

        th_pool = []
        for i in range(__g_max_threading):
            th = threading.Thread(target=th_port_detect)
            th_pool.append(th)
            th.start()

        for i in range(__g_max_threading):
            threading.Thread.join(th_pool[i])

        # Save available IPs to file
        if len(__g_alive_list) > 0:
            f = open('alive.ip', 'a')
            ips = '\n'.join(__g_alive_list)
            f.writelines(ips)
            f.close()

        print '-> Detecting alive IP FINISHED! '

    def start(self):
        """Start
        """
        git = get_ips_from_github()
        spf = nslookup()
        sort_ip_list(git, spf)
        # detect_alive_ip()

    def __init__(self):
        pass

if __name__ == '__main__':
    pass
