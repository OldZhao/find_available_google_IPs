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
        global ggg
        print ggg

    def __init__(self):
        print 'class'
        print sys.argv[:]
        # print self.__a
        # print self.__class__.__a
        # print self.b
        # print self.__class__.b

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "hi:o:")
    input_file = ""
    output_file = ""
    for op, value in opts:
        if op == "-i":
            input_file = value
        elif op == "-o":
            output_file = value
        elif op == "-h":
            sys.exit()

    k = abc()
    k.ex()
