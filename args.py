#!/usr/bin/env python
# -*- coding:utf-8 -*-


import urllib
import os
import os.path
import sys
import platform
import getopt
import re
import httplib
import IPy
import time
import socket
import random


class args(object):

    """ test """

    def __init__(self, arg=None):
        super(args, self).__init__()
        self.arg = arg

    def get_url_iplist(self, url=None):
        reip = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/0-9]*')
        reg = re.compile(r'as-name:\s+GOOGLE')
        rey = re.compile(r'as-name:\s+YOUTUBE')
        print '-->', url
        iplist = []
        url2 = []
        path = os.path.join(self.__abspath, 'web.tmp')
        urllib.urlretrieve(url, path)
        with open(path, 'r') as f:
            found = False
            for line in f:
                if not found:
                    if len(re.findall(reg, line)) > 0 or len(re.findall(rey, line)) > 0:
                        found = True
                        iplist.extend(re.findall(reip, line))
                    else:
                        if 'accept AS-GOOGLE' in line or 'accept AS-YOUTUBE' in line:
                            url2.extend(re.findall(r'AS[0-9]{3,}', line))
                        elif 'Google' in line or 'YOUTUBE' in line:
                            iplist.extend(re.findall(reip, line))
                else:
                    for line in f:
                        iplist.extend(re.findall(reip, line))
        iplist = {}.fromkeys(iplist).keys()
        url2 = {}.fromkeys(url2).keys()
        print '\turl2=%s,iplist=%s' % (len(url2), len(iplist))
        return url2, iplist

    def test_args(self):
        a = ['cfdfa000', 'd8495900', 'adc28c00', '46208500', '42f94f00', 'adc22700', 'c0b20000', '3f754400', '4a7d8b00', '4a7d1100', '42f94800', '6c3b5000', '4a7d9400', '4a7dc400', 'adc24e00', '4a7d8d00', '4a7df500', '40e9a400', '80fca00', '46208200', 'd075f200', '4a7d8e00', '6cb10000', '4a7dcb00', '4a7d3a00', '4a7d7700', '480ef400', '40e9a800', 'c27a5100', 'adc24900', '4a7dc100', '4a7dbb00', '4a7d8600', 'adff7000', '46208400', '42f94000', '42f94600', '4a7dbe00', '3f6e4300', '42f94a00', '4a7dce00', '40e9a000', '40e9a100', 'adc25c00', '822d000', '42f94500', '68841400', '4a7d1300', '4a7d8300', '42660400', 'adc24c00', '822d800', '4a7d4b00', '4a7d1000', 'a2d89400', 'd155ee00', 'adc28e00', '400f7200', '400f7700', '4a7d8900', '4a7d8800', '4a7d1200', '4a7dea00', 'adc24f00', '46208c00', '42f94000', '4a7d4400', '6caac000', '46208700', 'c09e1c00', '4a7df400', 'd075f000', 'c0c8e000', 'd1558000', '4a7d8200', '42f94300', 'd8495800', '4a7dcd00', 'd075fe00', '1020300', '4a7de800', 'adc25a00', 'adc26000', '4a7d2b00', '4a7d1c00', 'adc27900', '46209000', '400f7100', '4a7dba00', '4a7d1f00', 'd8ef2700', '4a7dc600', '4a7dcf00', 'd075ee00', '8080800', 'adc24100', '4a7d8a00', '823c000', 'adc2c200', 'd075fb00', 'adc27800', '40e9b500', '4a7de500', 'd075e100', '41c72000', 'd075ff00', '4a7db000', '40e9ab00', 'c18e7d00', 'adc27d00', 'd075fc00', 'd0419800', '4a7d1d00', '400f7c00', 'd8495f00', '4a7d4500', 'adc24200', '4a7dca00', '400f7000', 'adc24400', 'd075e700', '400f7000', 'adc27100', '40e9a300', '40e9bb00', 'd075fa00', '92940000', '68c40000', '42660200', 'd8ef2000', 'd8495100', '8080400', '40e9a000', '3f750e00', 'd075e500', '480ec000', '6cb10000', '42f94e00', 'adc22d00', '4a7d5800', '4a7de600', '4a7d8100', '4a7d8500', '4a7d4600', 'adc25900', 'adc24000', '40e9ba00', 'adc22200', 'adc25b00', '4a7d0000', '4a7d1a00', '4a7d8f00', 'd8495200', '4a7d3f00', '4a7dc300', '46209e00', '8efa0000', '3f75d700', 'adc27c00', 'adc27700', '17fb8000', 'a2deb000',
             '4a7dee00', 'adc24800', '4a7d7600', '3f600400', '46208000', '40e9a700', '6bb2c000', '4a7d7900', 'd075ef00', '4a7dbc00', '4a7db900', 'c1210500', '4a7de200', '4a7de300', '40e9b200', 'adc22b00', 'd8495e00', 'adc22e00', '1000000', 'adc2c100', '400f7800', 'd8ef2200', '4a7d7500', 'adc22c00', 'adc27000', 'adc2c300', '4a7de400', '4a7db200', '4a7d1e00', '42f94b00', '1010100', '4a7db600', 'c27a5200', '4a7dcc00', '42660000', 'd8ef2300', 'adc22100', '4a7d2e00', 'd83ac000', 'd075e600', '40e9a900', '4a7d1600', '4a7de900', 'adc22f00', '40e9b600', 'c27a5000', 'c0771000', 'd8495500', 'd075e900', 'adc26200', '68840000', 'acd90000', 'adc28d00', '40e9bd00', '40e9b800', '42660300', '4a7db100', '4a7d2900', '4a7d1800', '4a7dc800', 'd075e000', '4a7db700', 'adc24700', '40e9a600', 'adc24300', '4a7df600', '40e9b700', 'adc22400', '4a7db800', '3f584900', '46209200', '4a7d1b00', 'adc22900', '4a7def00', 'adc27600', '4a7de700', '46208600', '4a7d3500', '4a7d2f00', 'adc22000', '42f94400', 'adc20000', 'd0419b00', 'adc22800', '6ba7a000', 'adc22300', '42f94700', '46209400', '4a7d9700', 'adc22500', 'acfd0000', '4a7d5a00', 'adc28800', '46208300', '4a7ded00', '4a7d2a00', '42f94200', '4a7d7100', '4a7d1400', 'adc27f00', 'd075e000', '4a7d8000', '4a7db500', '4a7dc200', '4a7deb00', '4a7d3600', '9503b100', '4a7de000', 'adc26300', 'd075ec00', '40e9b900', '40e9b400', '400f7500', '4a7d0600', '17ff8000', '46208e00', '4a7d1900', '17ec3000', '4a7d9500', 'd815a000', '71c56a00', '41c4bc00', '4a7d9600', '40e9a500', 'd8ef2400', '400f7e00', '2e1cf600', '823c800', '4a7d1500', '4a7d4900', 'd8ef2000', '17e48000', '6bbc8000', 'c7dfe800', '40e9a200', '689a0000', 'c7c07000', 'adc27500', 'adc24d00', '4a7dec00', 'd8ef2600', 'd8ef3c00', '4a7dc000', '4a7d4700', '4a7d4800', '4a7dc900', 'adc25d00', '4a7d2d00', 'd8ef2100', '400f7300', 'adc22600', '82d30000', '4a7de100', '40e9b000', '2e1cf700', 'adc22a00', 'adc27e00', '4a7d1700', '4a7d4a00', '42f94c00', '480ee400', '4a7d2800', '40e9b300']
        b = ['20', '24', '24', '24', '24', '24', '15', '24', '24', '24', '24', '20', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '17', '24', '24', '24', '23', '24', '24', '24', '24', '24', '24', '20', '24', '19', '24', '24', '24', '24', '24', '24', '24', '24', '21', '24', '24', '24', '24', '24', '24', '21', '24', '24', '22', '24', '24', '24', '24', '24', '24', '24', '24', '24', '23', '24', '24', '18', '24', '22', '24', '24', '19', '17', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '21', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '22', '24', '24', '24', '24', '24', '24', '20', '24', '24', '24', '24', '24', '24', '24', '17', '14', '24', '19', '24', '24', '19', '24', '24', '18', '24', '24', '24', '23', '24', '24', '24', '24', '24', '24', '24', '24', '24', '16', '24', '24', '24', '24', '24', '24', '15', '24', '24', '24', '19', '21',
             '24', '24', '24', '24', '19', '24', '18', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '20', '24', '24', '24', '19', '24', '24', '24', '24', '24', '24', '24', '20', '24', '24', '24', '14', '16', '24', '24', '24', '24', '24', '24', '24', '24', '19', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '16', '24', '24', '19', '24', '24', '23', '24', '24', '16', '23', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '23', '24', '24', '24', '24', '24', '24', '24', '24', '17', '23', '24', '20', '24', '20', '24', '24', '24', '24', '24', '24', '24', '21', '24', '24', '24', '18', '17', '21', '24', '15', '22', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '16', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24', '24']
        return a, b

    def ff(self, url_txt=''):
        url = []
        url_txt = '%s/AS[0-9]{3,}' % url_txt
        r = re.compile(url_txt)
        with open('html.txt', 'r') as f:
            for line in f:
                url.extend(re.findall(r, line))
        url = {}.fromkeys(url).keys()
        print url
        print 'get url=%s' % len(url)

        with open('ipinfo.url.list', 'w') as f:
            f.write('\n'.join(url))

        url2 = url[:]
        list2 = []
        index = 0
        u = None
        while True:
            if len(url) > 0:
                u = url.pop(0)
            else:
                break
            u3, l3 = self.get_url_iplist(u)
            list2.extend(l3)
            for x in u3:
                x = '%s/%s' % (url_txt, x)
                if x not in url2:
                    url.append(x)
            index = index + 1
            print '--> index=', index

        iplist = {}.fromkeys(list2).keys()
        print 'get total ip and range=', len(iplist)
        with open('ipinfo.ip.range', 'w') as f:
            f.write('\n'.join(iplist))
        tip = []
        for ip in iplist:
            if '0.0.0.0' not in ip:
                ipy = IPy.IP(ip)
                tip.extend([str(x) for x in ipy])
        tip = {}.fromkeys(tip).keys()
        print 'caculated ip list =', len(tip)
        with open('ipinfo.ip.list', 'w') as f:
            f.write('\n'.join(tip))
        print 'set diff'
        s1 = set(tip)
        ip_list = self.get_iplist_from_local_file('google.ip')
        s2 = set(ip_list)
        s3 = s1 - s2
        print 'len(s1)=%s,len(s2)=%s' % (len(s1), len(s2))
        print 's1-s2 lenth=', len(s3)

        with open('diff.ip.list', 'w') as f:
            f.write('\n'.join(s3))
        print '<-- end'
