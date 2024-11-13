#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
プログラム実行方法
$ sudo python mn_topology.py
'''

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.log import setLogLevel

class MyTopo(Topo):
    
    # h1 <-> s1 <-> h2
    def build(self):

        #ホストの追加
        Host1 = self.addHost("h1", ip="10.0.0.1", mac="00:00:00:00:00:01")
        Host2 = self.addHost("h2", ip="10.0.0.2", mac="00:00:00:00:00:02")

        #OFSの追加
        Switch1 = self.addSwitch("s1", ip="10.0.0.3", dpid="0000000000000001")
        Switch2 = self.addSwitch("s2", ip="10.0.0.4", dpid="0000000000000002")

        #リンクの追加
        self.addLink(Host1, Switch1, port2=1)
        self.addLink(Host2, Switch2, port2=4)
        self.addLink(Switch1, Switch2, port1=2, port2=3)

def setup():
   
    # Mininetトポロジの作成
    topo = MyTopo()
    net = Mininet(topo=topo, controller=RemoteController("c0", ip="127.0.0.1"), link=TCLink)

    # hostのipv6の無効化
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    # OFSのipv6の無効化
    for sw in net.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    net.start()
    print("*** Dumping host connections")
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info") # mininet起動時のログ表示用
    setup()