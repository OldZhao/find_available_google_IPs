#!/usr/bin/env python
# -*- coding:utf-8 -*-

import urllib
import os
import os.path
import re
import httplib
import threading
import subprocess


class abc(object):

    """
    """
    __a = 3
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
        #raise NameError,'no name'
        #raise XXoo,'no name'
        raise Warning,'no name'
        print 'ss'


    def __init__(self):
        print self.__a
        self.__a = 0


k = abc()
k.ex()
