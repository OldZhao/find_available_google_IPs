#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
A useful tool that helping to find survived google's IPs.

Google was blocked randomly and DNS-polluted by the GOV of TIANCHAO since
many years ago, and it getting worst now. It's very difficult to visit
google website inside the WALL. Fortunately, not all of the IPs were in the
black list of THE GREAT FIRE WALL. With shattered hopes, we try to find out
the IP which is survived if we're lucky enough.

Anyway, THE BEST WAY to get through the WALL is using a VPN or PROXY.
(e.g: shadowsocks)

"Freedom has many difficulties and democracy is not perfect,
but we have never had to put a wall up to keep our people in,
to prevent them from leaving us."
--1963.6.25

Further Information might be available at:
https://github.com/scymen/find_available_google_IPs
"""


import urllib
import os
import os.path
import sys
import platform
import getopt
import re
import httplib
import threading
import subprocess
import IPy
import time
import socket
import random


class FindIP(object):

    __version = '1.1'
    __pyenv = '2.7.6'
    __is_win_os = True
    __abspath = os.path.abspath(os.path.dirname(sys.argv[0]))
    __source_ip_list = []
    __source_port_list = []
    __total_alive_ip = 3
    __avgtime = 500
    __alive_ip_list = {}  # key=ip,value=[avg-time,opened-ports]
    __is_exit = False  # multi-threads exit-signal
    __g_mutex = None  # threading.Lock()
    __g_mutex_save = None  # threading.Lock()

    def get_iplist_from_local_file(self, path=None):
        if not path or len(path.strip()) < 1:
            raise ValueError('Invalidate file path:', path)
        else:
            print '-> read file: ', os.path.split(path)[1]
        ip_list = []
        reip = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/0-9]*')
        tmplist = []
        with open(path, 'r') as f:
            for line in f:
                tmplist.extend(reip.findall(line))
                if self.__is_exit:
                    sys.exit(0)
        for ip in tmplist:
            if '/' in ip:
                ipy = IPy.IP(ip)
                ip_list.extend([str(x) for x in ipy])
            else:
                ip_list.append(ip)
            if self.__is_exit:
                sys.exit(0)
        ip_list = {}.fromkeys(ip_list).keys()
        print '\tget %s IPs' % len(ip_list)
        return ip_list

    def get_iplist_from_web(self, url=None):
        print '-> Downloading :%s' % url

        if not url or len(url.strip()) < 4:
            raise ValueError('Invalidate URL')

        path = os.path.join(self.__abspath, 'web.ip.tmp')
        urllib.urlretrieve(url, path)

        print '\tsave to web.ip.tmp'
        print '\tAnalyzing ...'
        re_ip = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/0-9]*')
        ip_list = []

        ip_list = self.get_iplist_from_local_file(path)

        os.remove(path)

        path = os.path.join(self.__abspath, 'web.ip.list')
        with open(path, 'w') as f:
            f.write('\n'.join(ip_list))

        print '\tDone! %s IPs save to web.ip.list\n' % len(ip_list)
        return ip_list

    def get_iplist_by_nslookup(self):
        # manual:https://support.google.com/a/answer/60764?hl=zh-Hans
        # nslookup -q=TXT _spf.google.com 8.8.8.8
        # nslookup -q=TXT _netblocks.google.com 8.8.8.8
        # nslookup -q=TXT _netblocks2.google.com 8.8.8.8
        # nslookup -q=TXT _netblocks3.google.com 8.8.8.8
        print "-> Query Google's SPF record..."
        # firstly, try to retrieve the SPF records
        spf = 'nslookup -q=TXT _spf.google.com 8.8.8.8'
        domain = []
        for i in range(1, 6):  # try 5 times if timeout or sth err
            if self.__is_exit:
                sys.exit(0)
            p = subprocess.Popen(spf, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,   stderr=subprocess.PIPE, shell=True)
            out = p.stdout.read()
            if '~all' not in out:
                print '\tTimeout,try again (%s) ...' % i
                continue
            else:
                r = re.compile(r'[_A-Za-z0-9]+.google.com')
                domain = r.findall(out)[1:]
                print "\tRecieved: ",
                print domain
                break

        if len(domain) == 0:
            print '\tFailed!! Get nothing.'
            return None

        # secondly, query ip range by every single SPF record.
        print '\tQuery IP range...'
        r4 = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+')
        # r6 =re.compile()
        iprange = []
        for d in domain:
            if self.__is_exit:
                sys.exit(0)
            cmd = 'nslookup -q=TXT %s 8.8.8.8' % d
            for j in range(5):  # try 5 times if sth err
                if self.__is_exit:
                    sys.exit(0)
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, shell=True)
                out = p.stdout.read()
                if '~all' not in out:
                    print '\tTimeout,try again (%s) ...' % j
                    continue
                else:
                    iprange.extend(r4.findall(out))
                    break

        if len(iprange) == 0:
            print '\tFailed!! Get nothing.'
            return None
        else:
            print iprange
        # thirdly, caculate ip list with the ip range
        print '\tCaculate IP list:'
        ip_list = []
        for x in iprange:
            ips = IPy.IP(x)
            ip_list.extend([str(i) for i in ips])

        print '\tTotal: %s' % len(ip_list)
        # Write to file
        path = os.path.join(self.__abspath, 'google.ip')
        with open(path, 'w') as f:
            f.writelines('\n'.join(ip_list))

        print '\tSave IP list to file google.ip'
        return ip_list

    def detect_port(self, ip=None, ports=[], connect_timeout=2):
        """ return alive ports which was given in the ports-list
        """
        if not ip or not ports or len(ports) < 1:
            raise ValueError('Invalidate argument value.')
        port_list = []
        socket.setdefaulttimeout(connect_timeout)
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((ip, int(p)))
                port_list.append(p)
                s.close()
                # s.shutdown(1)
            except Exception, ex:
                # print ex
                pass
            finally:
                pass
            if self.__is_exit:
                sys.exit(0)
        return port_list

    def speed_test(self, ip=None, is_win_os=True):
        """ return the times(second) of PING responsed, otherwise return timeout
        """
        timeout = 9999.0
        if not ip:
            return timeout
        # if 'windows' in platform.system().lower():
        if is_win_os:
            p = subprocess.Popen(["ping.exe", ip], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,   stderr=subprocess.PIPE, shell=True)
            out = p.stdout.read()
            pattern = re.compile(r'\s=\s(\d+)ms', re.I)
            m = pattern.findall(out)
            if m and len(m) == 3:
                return float(m[2])
        else:  # Linux, MAC
            p = subprocess.Popen(["ping -c4 " + ip], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,  stderr=subprocess.PIPE, shell=True)
            out = p.stdout.read()
            out = out.split('\n')[-2]
            if 'avg' in out:
                out = out.split('/')[4]
                if out:
                    return float(out)
        return timeout

    def __get_one_ip(self):
        self.__g_mutex.acquire()
        if not self.__source_ip_list or len(self.__source_ip_list) == 0:
            self.__g_mutex.release()
            return None
        ip = self.__source_ip_list.pop(0)
        self.__g_mutex.release()
        return ip

    def __save_ip(self, ip, avgtime):
        self.__g_mutex_save.acquire()
        self.__alive_ip_list[ip] = avgtime
        total = len(self.__alive_ip_list)
        self.__g_mutex_save.release()
        return total

    def __get_total_alive_ip(self):
        self.__g_mutex_save.acquire()
        total = len(self.__alive_ip_list)
        self.__g_mutex_save.release()
        return total

    def __detect_ip(self):
        # loop to detect alive IP and opened-port
        while True:
            if self.__is_exit:
                break
            ip = self.__get_one_ip()
            total = self.__get_total_alive_ip()
            if ip and total < self.__total_alive_ip:
                if '443' in self.detect_port(ip, self.__source_port_list):
                    t = self.speed_test(ip, self.__is_win_os)
                    if t <= self.__avgtime:
                        total = self.__save_ip(ip, t)
                        print '\tsurvived ip=%-16s time=%-8s [SAVED]' % (ip, t)
                        if total >= self.__total_alive_ip:
                            break
                    elif t > self.__avgtime and t < 9999:
                        print '\tsurvived ip=%-16s time=%-8s [IGNORE]' % (ip, t)
            else:
                break

    def stop_multi_thread(self):
        self.__is_exit = True

    def start_multi_thread(self, iplist=[], portlist=[], max_threading=10, saveto_file_path='survived.ip'):
        if not iplist or len(iplist) < 1 or not portlist or len(portlist) < 1 or not saveto_file_path:
            raise ValueError('ZERO ip in list')
        max_threading = 5 if max_threading < 5 else max_threading
        max_threading = 1024 if max_threading > 1024 else max_threading
        self.__source_ip_list = iplist
        self.__source_port_list = portlist
        self.__g_mutex = threading.Lock()
        self.__g_mutex_save = threading.Lock()

        self.__is_exit = False

        print '-> Searching IPs ...\
                \n\tit will take several minitues, be patient...\
                \n\tOR press Ctrl-C to interrupt.\n'
        th_pool = []
        for i in range(max_threading):
            th = threading.Thread(target=self.__detect_ip)
            th.setDaemon(True)  # important
            th_pool.append(th)
            th.start()

        # normally, current thread should waiting for all sub-threads finish it's job and exit.
        # but the caller can call method stop_multi_thread (this method set self.__is_exit = True)
        # to send an exit-signal，to ask sub-threads exit gently,
        # but current thread may take few seconds to wait all sub-thread
        # exit-signal.
        # print 'joint all the sub-thread'
        for t in th_pool:
            t.join()

        # print 'all sub-thread exit'
        if self.__is_exit:
            pass
            # print '\n-->> user interrupt\n'
        # Save IPs to file
        path = os.path.join(self.__abspath, 'out')
        if not os.path.isdir(path):
            os.mkdir(path)
        path = os.path.join(path, saveto_file_path)
        arr = {}
        if len(self.__alive_ip_list) > 0:
            arr = sorted(self.__alive_ip_list.items(), key=lambda x: x[1])
            with open(path, 'w') as f:
                for k in arr:
                    f.writelines('%-15s   %-4s \n' % (k[0], k[1]))

        print '-> Save %s IPs to file %s' % (len(self.__alive_ip_list), saveto_file_path)
        return arr

    def output_format_file(self, ip_list, output_file):
        """Generate format file : host , goagent proxy.ini
        """
        outpath = os.path.join(self.__abspath, 'out')
        if not os.path.isdir(outpath):
            os.mkdir(outpath)
        if not ip_list:
            return None
        # goagent format
        with open(os.path.join(outpath, output_file), 'w') as f:
            f.writelines(
                '## Open the config file proxy.ini in the folder goagent/local,\n')
            f.writelines(
                '## and replace the [iplist] node with the following txt\n')
            f.writelines(
                '## DO NOT MODIFY the line (google_ipv6 = xxx:xxx::...) if it exist. \n')
            f.writelines('\n\n[iplist]\n')
            f.writelines('google_cn = %s\n' % '|'.join(ip_list[0:5]))
            f.writelines('google_hk = %s\n' % '|'.join(ip_list[0:5]))
            f.writelines('google_talk = %s\n' % '|'.join(ip_list[0:5]))

        print '-> format output, save to folder [out]'

    def __init__(self, t, n):
        if 'windows' in platform.system().lower():
            self.__is_win_os = True
        else:
            self.__is_win_os = False
        self.__avgtime = t
        self.__total_alive_ip = n


def print_usage():
    print u"\
    Usage:\n \
        findip.py [-t|-n|-m number] [-h|--help] \n\
    \n\
    For example:\n\
        findip.py \n\
        OR \n\
        findip.py -t 250 -n 5\n\
        OR \n\
        findip.py -t 200 -n 5 -m 20 \n\
    \n\
    Options:\n\
        -t : default=200, the average time(ms) of PING test response, \n\
             the one >=200 will be ignore.\n\
        -n : default=5, total of available IPs that you want.\n\
        -m : default=20, max number of threading to work.\n\
        -h|--help: print usage\n\
        \n\
    How to stop: \n\
        press ctrl-c  \n\
        It will delay few seconds to exit all the threads. \n\
    Output:\n\
        the results are in the folder 'out' \n\
        ├─out\n\
           ├─hosts    =>  update the hosts file of your system \n\
           └─goagent  =>  for the node [iplist] of proxy.ini in goagent\n\
    "


if __name__ == '__main__':
    t = 500
    n = 3
    m = 10
    url = ''
    f = ''
    use_a = False
    use_g = False
    fbase = os.path.abspath(os.path.dirname(sys.argv[0]))
    try:
        opts, args = getopt.getopt(sys.argv[1:], "a:g:f:url:t:n:m:h", ["help"])
        for opt, arg in opts:
            if opt == '-h' or opt == '--help':
                print_usage()
                sys.exit(0)
            if opt == '-t':
                t = int(arg)
            if opt == '-n':
                n = int(arg)
            if opt == '-m':
                m = int(arg)
            if opt == '-url':
                url = arg
            if opt == '-g':
                use_g = True
            if opt == '-f':
                f = arg
                if '/' not in f and '\\' not in f:

                    f = os.path.join(fbase, f)
                if not os.path.isfile(f):
                    print 'Error: file not found.\n'
                    print_usage()
                    sys.exit(0)
            if opt == '-a':
                use_a = True
    except:
        print_usage()
        sys.exit(0)

    l1 = []

    fip = FindIP(t, n)

    p = os.path.join(fbase, 'google.ip')
    if os.path.isfile(p):
        l1 = fip.get_iplist_from_local_file(p)
    else:
        l1 = fip.get_iplist_by_nslookup()
    random.shuffle(l1)
    saveto_file_path = 'survived.ip'
    th = threading.Thread(
        target=fip.start_multi_thread, args=(l1, ['443'], m, saveto_file_path))
    th.setDaemon(True)
    th.start()

    #df = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'
    #fip = FindIP(t, n)
    ## iplist2 = fip.get_iplist_from_web(df)
    #iplist1 = fip.get_iplist_from_local_file(f)
    ## iplist3 = fip.get_iplist_by_nslookup()
#
    # random.shuffle(iplist1)

    # print fip.detect_port('seili.net',['80','443'])

#
    while True:
        alive = False
        try:
            time.sleep(0.5)
            if not th.isAlive():
                break
        except KeyboardInterrupt:
            fip.stop_multi_thread()
            print '---->>>    user interrupt   <<<-----'
            th.join(3)
            break

    out = os.path.join(fbase, 'out')
    p = os.path.join(out, saveto_file_path)
    if not os.path.isfile(p):
        raise EOFError(
            'the output file (%s) does not exist') % saveto_file_path

    survived_ips = []
    with open(p, 'r') as f:
        for line in f:
            survived_ips.append(line[0:16].strip())

    print '-> format output...'
    fip.output_format_file(survived_ips, 'for.goagent.txt')
    #p = os.path.join(out, 'for.goagent.txt')
    # with open(p, 'w') as f:
    #    f.writelines('|'.join(survived_ips[0:5]))

    print '-> FINISHED '


# = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'
