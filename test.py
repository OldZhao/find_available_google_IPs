#!/usr/bin/env python
# -*- coding:utf-8 -*-
# find available GOOGLE IP

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
    v = 'a'
    __var = 'kkk'
    g =3


    def s(self):
        global g =88
        print self.__var
        __var = 9
        print __var
        print self.__var
        print g

    def __init__(self):
        self.v = 'v'


k = abc()
k.s()
