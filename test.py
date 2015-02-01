#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib
import os
import sys
import getopt
import os.path
import re
import httplib
import threading
import subprocess
import time
import random
import telnetlib

ggg = 56


class abc(object):

    """
    """
    __a = 3
    b = 9
    __mutex = threading.Lock()

    def th(self):
        print self.__a
        pool = []
        for i in range(2):
            th1 = threading.Thread(target=self.run, args=[str(i)])
            pool.append(th1)
            th1.start()

        for i in range(2):
            pool[i].join()
        print ' ok'

    def run(self, name):
        for i in range(10):
            self.__mutex.acquire()
            self.__a += 1
            print ' %s  %s' % (name, self.__a)
            self.__mutex.release()

    def ex(self):
        global __a
        print ggg

    def stop(self):
        print self.b
        print self.__a

    def __init__(self):
        pass
        # print 'class'
        # print sys.argv[:]
        # print self.__a
        # print self.__class__.__a
        # print self.b
        # print self.__class__.b

import urllib
import httplib
import socket

h1='216.58.220.5'
h1='173.194.59.198'
h1='72.14.246.106'
h1='1.179.250.39'
h1='baidu.com'
h1='http://mail.qq.com/cgi-bin/loginpage'
port =443
timeout=4
aip=167773121
t1 = time.time()
#socket.setdefaulttimeout(timeout)
#s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#try:
#    s.connect((h1,port))
#    s.shutdown(2)
#    print '%d is open' % port
#except:
#    print '%d is down' % port   208.117.233.10
#64.15.126.242
import urllib2
t1=time.time()
x=urllib2.urlopen( 'https://64.15.126.242',None,5)
c= x.read()
t2=time.time()
print 'time=',t2-t1
if 'google.com' in c:
    print 'yes'
    print 'time=',time.time()-t2
else :
    print 'no'
print x.getcode()


ip='208.117.233.10'
ip='64.15.126.242'
c=httplib.HTTPSConnection(ip, 30)
response = c.getresponse()
result = str(response.status)+' ,'+response.reason
print result

sys.exit(0)



c = httplib.HTTPSConnection(h1, timeout=3)
print 'connect'
try:
    c.request("GET", "/")
    response = c.getresponse()
    if 404==response.status:
        print 'yes'
    result = str(response.status)+' ,'+response.reason
    print result
except Exception ,ex:
    print 'error->',ex


t2 = time.time()
print '\n time1=' , (t2 - t1)

#c = httplib.HTTPSConnection(h2, timeout=3)
#try:
#    c.request("GET", "/")
#    response = c.getresponse()
#    result = str(response.status)+' '+response.reason
#    print result
#except Exception ,ex:
#    print 'error',ex
#finally:
#    c.close()
#
#t3 = time.time()
#tn = telnetlib.Telnet(h2,port,timeout)
#tn.write('a')
#tn.close()
#t4 = time.time()
#print 'end'
#
#print '\n time2=' , (t4 - t3)



#t1 = time.time()
#a = [i for i in xrange(200000)]
#t2 = time.time()
#
#
#t3 = time.time()
#random.shuffle(a)
#
#t4 = time.time()
#print '\n time1=' , (t2 - t1)
#print '\n time2=' , (t4 - t3)

# if __name__ == '__main__':
#    print '__main__'
# else :
#    print ' not main'
# for i in range(10000):
#    try:
#        time.sleep(1)
#        print ' loop %s ' % i
#    except KeyboardInterrupt:
#        print ' ctrl-c'
#        break
# print ' exit'
# sys.exit(0)

#opts, args = getopt.getopt(sys.argv[1:], "t:m:n:h",['help'])
# print opts
# print args
# for a in args:
#    if a not in ('-t','-m','-n','-h','--help'):
#        print ' str help'
#        sys.exit(1)

# for op, value in opts:
#    if op not in ('-t','-m','-n','-h','--help'):
#        print op
#        print 'str help'
#        sys.exit(1)
#    else:
#        print 'ok'
