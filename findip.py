#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
A useful tool to find out the survived IP of google in TIANCHAO.

Google was blocked randomly and DNS Poisoning by the GFW of TIANCHAO since
many years ago, and it's getting worse now. It's very difficult to visit
google website inside the WALL. Fortunately, not all of the IPs were in the
black list of THE GREAT FIRE WALL. With shattered hopes, we try to find out
the IP which is survived if we're lucky enough.

Anyway, THE BEST WAY to get through the WALL is using a VPN or a PROXY.
(e.g: shadowsocks)
And THE BEST of THE BEST is ...

"Freedom has many difficulties and democracy is not perfect,
but we have never had to put a wall up to keep our people in,
to prevent them from leaving us."
-- John F. Kennedy 1963.6.25

Further Information might be available at:
https://github.com/scymen/find_available_google_IPs
"""


import urllib2
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
    __avgtime = (0, 500)
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
            path = os.path.join(self.__abspath, 'google.ip')
            with open(path, 'w') as f:
                f.writelines('\n'.join(iprange))

        # thirdly, caculate ip list with the ip range
        print '\tCaculate IP list:'
        ip_list = []
        for x in iprange:
            ips = IPy.IP(x)
            ip_list.extend([str(i) for i in ips])

        print '\tTotal: %s' % len(ip_list)
        # Write to file
        path = os.path.join(self.__abspath, 'google.ip.txt')
        with open(path, 'w') as f:
            f.writelines('\n'.join(ip_list))

        print '\tSave IP list to file google.ip'
        return ip_list

    def get_iplist_from_unofficial(self):
        print '-> get ip list from UNOFFICIAL source...\n\tbe patient...'
        import args
        a = args.args()
        iplist = []
        i1, i2 = a.test_args()
        for i in xrange(0, len(i1)):
            p = '0x%s/%s' % (i1[i], i2[i])
            ip = IPy.IP(p)
            for x in ip:
                iplist.append(str(x))
        iplist = {}.fromkeys(iplist).keys()
        print '\tget %s IPs' % len(iplist)
        return iplist

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

    def detect_http_ssl(self, ip=None, connect_timeout=2):
        """ return True if connect successed
        """
        if not ip:
            return False
        c = httplib.HTTPSConnection(ip, timeout=connect_timeout)
        try:
            c.request("GET", "/")
            response = c.getresponse()
            #result = str(response.status)+' ,'+response.reason
            if 200 == response.status:
                return True
            else:
                return False
        except Exception, ex:
            return False
            # print 'error',ex

    def detect_http(self, ip=None, connect_timeout=2, via_ssl=True):
        """ return True if connect successed
        """
        if not ip:
            return False
        try:
            url = 'https://%s' % ip
            if not via_ssl:
                url = 'http://%s' % ip
            c = urllib2.urlopen(url, None, connect_timeout)
            if 200 == c.getcode() and '<title>Google</title>' in c.read():
                return True
            else:
                return False
        except Exception, ex:
            return False
            # print 'error',ex

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
                # if '443' in self.detect_port(ip, self.__source_port_list):
                # if self.detect_http_ssl(ip):
                if self.detect_http(ip):
                    # sometimes port 443 is opened of an alive IP, but it may not
                    # service as a web server(maybe mail server), so we can't visit
                    # the web site via alive IP, we have to check the http-ssl
                    # connection
                    t = self.speed_test(ip, self.__is_win_os)
                    if t >= self.__avgtime[0] and t <= self.__avgtime[1]:
                        total = self.__save_ip(ip, t)
                        print '\tsurvived ip=%-16s time=%-8s [SAVED]' % (ip, t)
                        if total >= self.__total_alive_ip:
                            break
                    else:
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

    def output_format_file(self, ip_list, output_file, n=5):
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
            f.writelines('google_cn = %s\n' % '|'.join(ip_list[0:n]))
            f.writelines('google_hk = %s\n' % '|'.join(ip_list[0:n]))
            f.writelines('google_talk = %s\n' % '|'.join(ip_list[0:n]))

        print '-> format output, save to folder [out]'

    def __init__(self, t, n):
        if 'windows' in platform.system().lower():
            self.__is_win_os = True
        else:
            self.__is_win_os = False
        self.__avgtime = t
        self.__total_alive_ip = n


def print_usage():
    print u"\n\
Usage:\n \
    findip.py [-t|-n|-m|-o number] [-t from:to] \n\
              [-f file-path] \n\
              [-u url] [-agGD] [-h|--help] \n\
\n\
For example:\n\
    findip.py  \n\
    findip.py -u http://abc.com/ip_in_website.html \n\
    findip.py -f 'my_ip_list.txt' -g\n\
    findip.py -t 200:500 -n 5 -m 20 \n\
\n\
Options:\n\
    -t : the average time(ms) of PING test response,\n\
         a number or a range like 100:300.\n\
    -n : total of available IPs that you want.\n\
    -m : max number of sub-threads to work.\n\
    -f : file path, read a localfile which contains ip list.\n\
    -u : the url of web site which contains ipaddress.\n\
    -D : switch open = DO NOT detect IP and opned-port. \n\
         e.g: findip.py -u http://abc.com/ip_in_web.html -D\n\
         it means that get the IPs from the website and save to local-file.\n\
    -g : switch open = use local file 'google.ip'. \n\
    -G : switch open = query google SPF record to retrieve new IP list.\n\
    -o : the numbers of ip to output to the format file. \n\
    -a : unofficial, switch open = seaching ip witch another source.\n\
         last shot if you get NONE survived IP .\n\
    -h|--help: print manual.\n\
    \n\
How to stop: \n\
    press ctrl-C  \n\
    \n\
Output:\n\
    check the results in the folder 'out' \n\
"


if __name__ == '__main__':
    t = (0, 500)
    n = 3
    m = 30
    o = 5
    url = None
    f = None
    use_g = False
    use_G = False
    use_D = False
    use_a = False
    fbase = os.path.abspath(os.path.dirname(sys.argv[0]))
    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:u:t:n:m:o:agGhD", ["help"])
        for opt, arg in opts:
            if opt == '-h' or opt == '--help':
                print_usage()
                sys.exit(0)
            if opt == '-t':
                if ':' in arg:
                    t = tuple(int(x) for x in arg.split(':'))
                    if t[0] >= t[1]:
                        raise ValueError(" '-t' value error")
                else:
                    if int(arg) < 1:
                        raise ValueError(" '-t' value is a positive integer")
                    t = (0, int(arg))
            if opt == '-n':
                n = int(arg)
            if opt == '-m':
                m = int(arg)
            if opt == '-o':
                o = int(arg)
            if opt == '-u':
                url = arg
            if opt == '-g':
                use_g = True
            if opt == '-G':
                use_G = True
            if opt == '-a':
                use_a = True
            if opt == '-f':
                f = arg
                if '/' not in f and '\\' not in f:
                    f = os.path.join(fbase, f)
                if not os.path.isfile(f):
                    raise Exception(" file not found")
            if opt == '-D':
                use_D = True
    except Exception, ex:
        # except getopt.GetoptError:
        print ex
        print_usage()
        sys.exit(0)

    iplist = []

    fip = FindIP(t, n)

    if url:
        iplist.extend(fip.get_iplist_from_web(url))
    if f:
        iplist.extend(fip.get_iplist_from_local_file(f))
    if use_G:
        p = os.path.join(fbase, 'google.ip')
        if os.path.isfile(p):
            os.remove(p)
        use_g = True
    if not use_a:
        if use_g or (not url and not f):
            p = os.path.join(fbase, 'google.ip')
            if os.path.isfile(p):
                iplist.extend(fip.get_iplist_from_local_file(p))
            else:
                iplist.extend(fip.get_iplist_by_nslookup())
    else:
        iplist.extend(fip.get_iplist_from_unofficial())

    # print 'lenghth=', len(iplist)
    if use_D:
        print '-> FINISHED'
        sys.exit(0)

    random.shuffle(iplist)
    saveto_file_path = 'survived.ip'
    th = threading.Thread(
        target=fip.start_multi_thread, args=(iplist, ['443'], m, saveto_file_path))
    th.setDaemon(True)
    th.start()

    while True:
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

    random.shuffle(survived_ips)
    print '-> format output...'
    fip.output_format_file(survived_ips, 'for.goagent.txt', o)

    print '-> FINISHED '


# = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'
