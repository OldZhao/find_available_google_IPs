#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
A useful tool that helping to find available google's IPs.

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
#import shutil
import time
#import logging
#import logging.handlers


class FindIP(object):

    """Find out available Google's IP list in China ,and speed test
    """
    __version = '1.0'
    __pyenv = '2.7.6'
    __os_win = True
    __abspath = os.path.abspath(os.path.dirname(sys.argv[0]))

    __max_threading = 10
    __ipsource = 'all'
    __count = 10
    __avgtime = 200
    __github_url = ''
    __local_ip_file_path = ''
    __out_dir = os.path.join(__abspath, 'out')
    __in_dir = 'in'

    __source_list = []  # store all IPs
    # store alive IPs, key:IP  value:PING response agverage time
    __alive_list = {}
    __is_exit =False  # exit-signal

   # Normally the longer distance, the more It spends time on connection.
    __area_weight = {'Bulgaria': 0,
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
                     'Russia': 7,
                     'Saudi Arabia': 0,
                     'Serbia': 0,
                     'Singapore': 9,
                     'Slovakia': 0,
                     'Taiwan': 9,
                     'USA': 8,
                     'America': 8,
                     'Thailand': 7}

    def __get_iplist_from_github(self, url=''):
        """Download the IP-list-file from github.com,
        and save to file github.ip

        output format example:
            area=Hong Kong
            1.2.3.4
            5.6.7.8

        Args:
            url, default='https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'

        Returns:
            A dictionary with key(the area name) and value(IP list),
            If failed, return None
        """
        if not url:
            print '-> Empty URL, use default value $s' % self.__github_url
            # return None
            #raise 'URL can NOT be empty'

        print '-> Downloading file from github.com...',
        path = os.path.join(self.__abspath, 'github.ips.source')
        try:
            urllib.urlretrieve(url, path)
            print ' [ok]'
        except IOError as e:
            print ' [faild]'
            return None

        print '-> Analyzing file...'
        re_area = re.compile('>\w+\s?\w+<', re.I)
        re_ip = re.compile('\d+.\d+.\d+.\d+')
        dic = {}
        f = open(path, 'r')
        key = ''
        lst = list()
        for line in f:

            if self.__is_exit:
                f.close()
                sys.exit(0)

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
        os.remove(path)
        # write to file github.ip
        path = os.path.join(self.__abspath, 'github.ip')
        f = open(path, 'w')
        total = 0
        for k in dic:
            total += len(dic[k])
            f.writelines('area=' + k + '\n')
            ips = '\n'.join(dic[k]) + '\n\n'
            f.writelines(ips)
        f.close()
        print '-> Done! Get %s IPs from Github, save to file [github.ip]\n' % total
        return dic

    def __get_iplist_by_nslookup(self):
        """-> Query Google's SPF record to retrieve the range of IP address

        Args:
            None

        Returns:
            A dictionary with key:USA and value(IP list),
            If failed, return None

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

            if self.__is_exit:
                sys.exit(0)

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

            if self.__is_exit:
                sys.exit(0)

            cmd = 'nslookup -q=TXT %s 8.8.8.8' % d
            # try 5 time if time out
            for j in range(5):

                if self.__is_exit:
                    sys.exit(0)

                p = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True)
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

        print '-> Change to IP list:'

        ip_list = []
        total = 0
        for x in arr:

            if self.__is_exit:
                sys.exit(0)

            ips = IPy.IP(x)
            f = [str(i) for i in ips]
            print '-> Get %s IPs' % len(f)
            total += len(f)
            ip_list.extend(f)

        print '-> Total: %s' % total
        # Write to file
        path = os.path.join(self.__abspath, 'nslookup.ip')
        f = open(path, 'w')
        try:
            f.writelines('\n'.join(ip_list))
            print '-> Save IP list to file [nslookup.ip]'
        except IOError:
            print 'Error : save to file error.'
        finally:
            f.close()
        dic = {}
        dic['USA'] = ip_list
        return dic

    def __sort_ip_list(self, github_ip_list, nslookup_ip_list):
        """Sort the IP list by area-weight,
        the result will be stored in self.__source_list
        """
        # filter bad network line
        #if github_ip_list:
        #    for k in self.__area_weight:
        #        if self.__area_weight[k] < 7 and k in github_ip_list:
        #            del github_ip_list[k]

        if not github_ip_list:
            github_ip_list = {}

        # Merge two list
        if nslookup_ip_list:
            github_ip_list['USA'] = nslookup_ip_list['USA']

        del self.__source_list[:]

        for i in range(8, 10)[::-1]:
            for k in self.__area_weight:
                if self.__area_weight[k] == i and k in github_ip_list:
                    self.__source_list.extend(github_ip_list[k])
                    break

        print '   source IP list %s ' % len(self.__source_list)
        print '-> Sort IP list finished!'

    def __read_local_file(self, path):
        """Import IP list from a local file
        """

        ip_list = []
        f = open(path, 'r')
        p = re.compile('\d+.\d+.\d+.\d+')
        try:
            for line in f:
                match = p.search(line)
                if match:
                    ip_list.append(match.group(0))
        except:
            print 'read file error'
        finally:
            f.close()
        return ip_list

    def __th_port_detect(self):
        """Try to connect the host by https.
        """
        while True:

            if self.__is_exit:
                sys.exit(0)

            # If the total of alive-IPs >= self.__count , It's good enough
            # then go back
            if len(self.__alive_list) >= self.__count:
                break

            ip = self.__get_one_ip(self.__source_list)
            if not ip:
                break

            msg = 'Connecting %s ...' % ip
            c = httplib.HTTPSConnection(ip, timeout=3)
            try:
                c.request("GET", "/")
                response = c.getresponse()
                result = str(response.status)+' '+response.reason
                if '200 OK' in result:
                    msg += ' [OK] '
                    # PING test
                    at = self.__speed_test(ip)
                    msg += ' time=%s' % at
                    # Ignore the IP which response avgtime > self.__avgtime
                    if at >= self.__avgtime:
                        msg += ' [IGNORE]'
                    else:
                        msg += ' [SAVE]'
                        self.__alive_list[ip] = at
                else:
                    msg += ' [%s]' % response.status
            except:
                msg += ' [Timeout]'
            finally:
                c.close()

            tmp = '[total:%s] ' % len(self.__alive_list)
            msg = tmp + msg
            print msg

    def __get_one_ip(self, ip_list):
        if len(ip_list) == 0:
            return None
        else:
            # g_mutex.acquire()
            ip = ip_list.pop(0)
            # g_mutex.release()
            return ip

    def __speed_test(self, ip):
        """PING test
        """

        abnormal = 99999    # abnormal response time
        while True:
            if not ip:
                return abnormal

            if self.__os_win:
                p = subprocess.Popen(
                    ["ping.exe", ip], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,   stderr=subprocess.PIPE, shell=True)
                out = p.stdout.read()
                # pattern = re.compile(
                #   "Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", re.IGNORECASE)
                pattern = re.compile(r'\s=\s(\d+)ms', re.I)
                m = pattern.findall(out)
                # print out
                if m and len(m) == 3:
                    return int(m[2])
                else:
                    return abnormal
            # Linux, MAC or other system
            else:
                p = subprocess.Popen(["ping -c4 " + ip],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     shell=True)
                out = p.stdout.read()
                out = out.split('\n')[-2]
                if 'avg' in out:
                    out = out.split('/')[4]
                    if out:
                        return int(out)
                    else:
                        return abnormal
                else:
                    return abnormal

    def __detect_alive_ip(self):
        """ Detect alive IP with list self.__source_list

        Args:
            None
        """

        self.__alive_list.clear()
        if len(self.__source_list) == 0:
            return None

        th_pool = []
        for i in range(self.__max_threading):
            th = threading.Thread(target=self.__th_port_detect)
            th_pool.append(th)
            th.start()

        #for i in range(self.__max_threading):
        #    threading.Thread.join(th_pool[i])

        # loop waiting for ctrl-c signal
        while True:
            alive =False
            try:
                time.sleep(0.5)
                for i in range(self.__max_threading):
                    alive = alive or th_pool[i].isAlive()
                if not alive:
                    break
            except KeyboardInterrupt:
                print '->>>user cancel'
                self.stop()

        # Save available IPs to file
        path = os.path.join(self.__abspath, 'alive.ip')
        arr = {}
        if len(self.__alive_list) > 0:
            arr = self.__sort_ip_list_by_time()
            f = open(path, 'w')
            for k in arr:
                f.writelines('%-15s   %-4s \n' % (k[0], k[1]))
            f.close()

        print '-> Total alive IPs = %s ' % len(self.__alive_list)
        print '-> Save to file [alive.ip]'
        return arr

    def __sort_ip_list_by_time(self):
        """Sort IP list by time
        """
        arr = sorted(self.__alive_list.items(), key=lambda x: x[1])
        print arr
        return arr

    def __generate_format_file(self, alive_list):
        """Generate format file : host , goagent proxy.ini
        """

        if not os.path.isdir(self.__out_dir):
            # shutil.rmtree(self.__out_dir)
            # os.removedirs(self.__out_dir)
            os.mkdir(self.__out_dir)

        if not alive_list:
            return None

        path = os.path.join(self.__abspath, 'hosts.template')
        if not os.path.isfile(path):
            raise NameError('the template file [hosts.template] was missing')

        repeater = 3 if 3 <= len(alive_list) else len(alive_list)

        # host-file format
        f = open(path, 'r')
        txt = []
        try:
            for line in f:
                if '{ip}' in line:
                    txt.append(line.replace('{ip}', alive_list[0][0]))
                    # for i in range(0, repeater):
                    #    txt.append(line.replace('{ip}', alive_list[i][0]))
                elif '{time}' in line:
                    txt.append(
                        line.replace(
                            '{time}',
                            time.asctime(
                                time.localtime(
                                    time.time()))))
                else:
                    txt.append(line)
            f.close()
            f = open(os.path.join(self.__out_dir, 'hosts'), 'w')
            f.writelines(''.join(txt))
        except Exception as e:
            print 'Error : read/write file error'
            print e
        finally:
            f.close()

        # goagent format
        arr = [x[0] for x in alive_list]
        txt = '|'.join(arr)
        f = open(os.path.join(self.__out_dir, 'goagent'), 'w')
        try:
            f.writelines(txt)
        except:
            print 'Error : read/write file error'
        finally:
            f.close()

        print '-> format output, save to folder [out]'

    def start(self):
        """Start to work..
        """

        if self.__ipsource == 'github':
            git = self.__get_iplist_from_github(self.__github_url)
            self.__sort_ip_list(git, None)
        elif self.__ipsource == 'gspf':
            spf = self.__get_iplist_by_nslookup()
            self.__sort_ip_list(None,spf)
        elif self.__ipsource == 'all':
            git = self.__get_iplist_from_github(self.__github_url)
            spf = self.__get_iplist_by_nslookup()
            self.__sort_ip_list(git, spf)
        else:
            iplist = self.__read_local_file(self.__local_ip_file_path)
            self.__source_list = iplist

        print ' start function '
        print ' source list total ips %s ' % len ( self.__source_list)
        alist = self.__detect_alive_ip()
        self.__generate_format_file(alist)

        if self.__is_exit:
            print '\n == USER CANCEL ==\n'
        else:
            print '\n== DONE ==\n'

    def stop(self):
        self.__is_exit=True

    def __init__(
            self,
            ipsource='all',
            count=10,
            avgtime=200,
            maxthreading=10):
        """Initialize

        Args:
            ipsource options:
                1.'github'. Download the file from https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md
                2.'gspf'. Query Google's SPF record to retrieve the range of IP address
                3.'all'. Default option. Use github IP-list file AND query Google SPF.
                4. A file path. Read a local file that store IPs with one IP in a line
            count:
                default value=10, how many IPs you want, It will
                stop detecting while the amount of alive-IPs >= count.
            avgtime:
                default value=150ms, speed test,
                ignore the IP that PING response average time more than 150ms.

        Return:
            Class Instance
        """

        sopt = ('github', 'gspf', 'all')
        ipsource = ipsource.strip()
        if not ipsource:
            self.__ipsource = 'all'
        elif ipsource in sopt:
            self.__ipsource = ipsource
        else:
            ipsource = ipsource.strip('"')
            ipsource = ipsource.strip("'")
            if not os.path.isfile(ipsource):
                raise 'the path of local source IP file is invalid'
            else:
                self.__ipsource = 'file'
                self.__local_ip_file_path = ipsource

        self.__count = count
        self.__avgtime = 100 if avgtime <= 100 else avgtime
        self.__max_threading = maxthreading

        self.__github_url = 'https://raw.githubusercontent.com/Playkid/Google-IPs/master/README.md'

        if 'windows' in platform.system().lower():
            self.__os_win = True
        else:
            self.__os_win = False


def usage():
    print u"\
    Usage:\n \
        findip.py [-s string] [-t|-n|-m number] [-h|--help] \n\
    \n\
    For example:\n\
        findip.py \n\
        OR \n\
        findip.py -s all -t 250 -n 5\n\
        OR \n\
        findip.py -s c:/ip.txt -t 200 -n 5 -m 20 \n\
    \n\
    Options:\n\
        -s : source of IP list, \n\
             'github'. Download IP list from github.com \n\
             'gspf'. Query Google's SPF record to retrieve IP range \n\
             'all'. Default option. Use github IP-list AND query Google SPF. \n\
              A file path. Read a local file that store IPs with one IP in a line \n\
        -t : default=200, the average time(ms) of PING test response, \n\
             the one >=200 will be ignore.\n\
        -n : default=5, total of available IPs that you want.\n\
        -m : default=20, max number of threading to work.\n\
        -h|--help: print usage\n\
        \n\
    Output:\n\
        the results are in the folder 'out' \n\
        ├─out\n\
           ├─hosts    =>  update the hosts file of your system \n\
           └─goagent  =>  for the node [iplist] of proxy.ini in goagent\n\
    "


if __name__ == '__main__':
    t = 250
    n = 5
    m = 20
    s = ''
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:n:m:s:h", ["help"])
        # print os.getcwd()
        #path = os.path.abspath(os.path.dirname(sys.argv[0]))
        arr = ('-t', '-n', '-m', '-h', '-s', '--help')
        for a in args:
            if a not in arr:
                usage()
                sys.exit(1)

        for opt, arg in opts:
            if opt not in opt:
                usage()
                sys.exit(1)
            if opt == '-h' or opt == '--help':
                usage()
                sys.exit(1)
            if opt == '-t':
                t = int(arg)
            if opt == '-n':
                n = int(arg)
            if opt == '-m':
                m = int(arg)
            if opt == '-s':
                s = arg
    # except getopt.GetoptError, ValueError:
    except:
        print(">> I don't get It!\n")
        usage()
        sys.exit(1)

    fip = FindIP(s, n, t, m)
    fip.start()


#name = 'log'
#h = logging.getLogger(name)
#
#fh = logging.FileHandler('run.log')
# fh.setLevel(logging.DEBUG)
#
#console = logging.StreamHandler()
# console.setLevel(logging.DEBUG)
#
# formatter = logging.Formatter(
# '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# formatter = logging.Formatter(
#    '[%(levelname)s] - %(asctime)s - %(message)s')
#
# fh.setFormatter(formatter)
# console.setFormatter(formatter)
#
# h.addHandler(fh)
# h.addHandler(console)
#h.fatal('initialize log...')
#
#L = logging.getLogger('log')
# print L
# L.info('fck')
