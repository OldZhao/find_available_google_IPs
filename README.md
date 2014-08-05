Find available Google's IPs 
====

A useful tool that helping to find available Google's IPs.

If you are living in China, you known what I mean.

It works well with `Windows` and `Debian`, not yet tested on other platform.


How to start
----
1.You need python environment

<https://www.python.org/download/releases/2.7.8/>

please use python 2.7.x

2.run **python findip.py**

type `findip.py -h` or `findip.py --help` for help

3.when It finished, check the result in folder **out**

     ├─out
         ├─hosts    =>  for the hosts file of your system 
         └─goagent  =>  for the node [iplist] of proxy.ini in goagent

If there are enough alive-ips for you, press `Ctrl-c` to interrupt.

Others
----
This source calls system program `PING` and `nslookup`, if things go wrong, you should check that have they been installed?

Credits
----

The contributor of IPy : Maximillian Dornseif

<https://github.com/haypo/python-ipy>
 
 