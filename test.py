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
    global __var

    def s(self):
        print __var
        __var = 9
        print __var

    def __init__(self):
        self.v = 'v'
        global __var = 'mm'


k = abc()
k.s()
