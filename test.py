#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib
import os
import os.path
import re
import httplib
import threading
import subprocess

ggg=56

class abc(object):
    """
    """
    __a = 3
    b =9
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
        print self.__a
        print self.__class__.__a
        print self.b
        print self.__class__.b


k = abc()
k.ex()
