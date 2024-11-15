#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
import time

class L2monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]   #OpenFlow 1.3を利用

    def __init__(self, *args, **kwargs):
        super(L2monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {} # Datapathオブジェクトをidに結びつけて格納
        self.monitor_thread = hub.spawn(self._monitor) #スレッドの生成
        self.count = 0 #回数のカウントに利用


    #FlowStatsリクエストを5秒間隔で各OFSへ送信する
    def _monitor(self):

        while True:
            for datapath in self.datapaths.values():
                self._request_stats(datapath)   #FlowStatsの送信
            hub.sleep(5)

    #FlowStatsリクエストの送信を行う
    def _request_stats(self, datapath):

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)  #FlowStatsリクエストの送信

    #Flow Stats Replyを受け取ったときに実行される関数
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body  #bodyの取得
        datapath = ev.msg.datapath  #datapathオブジェクトの取得
        #優先度が10のフローエントリの統計情報を表示
        for stat in [flow for flow in body if flow.priority == 10]:
            '''
            self.count += 1 #countを1増やす
            print("===================統計情報を表示({}回目)===================".format(self.count))
            print("Datapath ID: {}を持つOFSのフローエントリの情報".format(datapath.id))
            print("Match条件 => in_port: {}, eth_src: {}, eth_dst: {}".format(stat.match["in_port"], stat.match["eth_src"], stat.match["eth_dst"]))
            print("Action => Port{}に出力".format(stat.instructions[0].actions[0].port))
            print("このフローエントリにマッチしたパケット数: {}, 総バイト数: {}".format(stat.packet_count, stat.byte_count))
            '''

            #デバッグ用         
            if  stat.instructions[0].actions[0].port == 2: #あるフローがポート2から出力されているとき...
                print("======================================================") 
                print("出力ポート2の内容です。")
                print("このフローエントリにマッチしたパケット数: {}, 総バイト数: {}".format(stat.packet_count, stat.byte_count))
                s1_out_now = stat.packet_count
                print("======================================================")             
                
            if stat.match["in_port"] == 3: #あるフローがスイッチのポート3から入力されているとき...
                print("======================================================") 
                print("入力ポート3の内容です。")
                print("このフローエントリにマッチしたパケット数: {}, 総バイト数: {}".format(stat.packet_count, stat.byte_count))
                s2_in_now = stat.packet_count
                print("======================================================") 

            #デバッグ用
            print("一つのflow stateメッセージ終了")
            print("s1_out: {}, s2_in: {}".format(s1_out_now, s2_in_now))
        

        # 課題2を以下に追記
        '''
        # 初期値の設定
        s1_now = 0
        s2_now = 0
        s1_ago = 0
        s2_ago = 0
        start_time = time.time()
        
        while True:
            for stat in [flow for flow in body if flow.priority == 10]:
                if stat.instructions[0].actions[0].port == 2:
                    s1_now = stat.packet_count
                if stat.match["in_port"] == 3:
                    s2_now = stat.packet_count

            elapsed_time = time.time() - start_time
            if elapsed_time >= 5:
                A = s1_now - s1_ago
                B = s2_now - s2_ago
                print("*************************************")
                if A == 0 and B == 0:
                    print("パケットが流れていません")
                else:
                    loss = (A - B) / A if A != 0 else 1
                    print("5秒毎のOFS間のパケットロス率: {:.2f}%".format(loss * 100))
                print("*************************************")
                s1_ago = s1_now
                s2_ago = s2_now
                start_time = time.time()
                '''
        


    #Switch Features Replyを受け取ったときに実行される関数
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath  # datapathオブジェクトを取得
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Datapathオブジェクトを格納
        if datapath.id not in self.datapaths:
            print("Hello Datapath ID {}".format(datapath.id))
            self.datapaths[datapath.id] = datapath

        #Table-missエントリーの作成
        match = parser.OFPMatch()   #Match条件なし(Any)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]   #OFCへパケット全体をPacket-InするActionの設定
        priority = 0    #優先度の設定
        self.add_flow(datapath, priority, match, actions)   #フローエントリの追加

        #課題1を以下に追記
        #ポート番号3000を破棄
        match1 = parser.OFPMatch(eth_type=0x0800, in_port=3, ip_proto=17, udp_dst=3000) #Match条件1 3000
        actions1 = []
        priority1 = 30
        self.add_flow(datapath, priority1, match1, actions1)

    #フローエントリをOFSに追加する際に使われる関数
    def add_flow(self, datapath, priority, match, actions):
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]  # ActionをInstruction化させる

        #Flow Modメッセージの作成
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)  #Flow Modメッセージの送信


    #Packet-Inによってパケットを受け取ったときに実行される関数
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]  #in_portの取得

        pkt = packet.Packet(msg.data)   #Ryuによるパケットの解析
        eth = pkt.get_protocols(ethernet.ethernet)[0]   #ethernetヘッダの取得

        dpid = datapath.id  #Datapath IDの取得
        dst = eth.dst   #宛先MACアドレスの取得
        src = eth.src   #送信元MACアドレスの取得

        #dpidとsrcをin_portに結びつける
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        '''
        print("============================================================")
        print("Datapath ID:{}を持つOFSの{}番ポートからPacket-Inされました！".format(dpid, in_port))
        print("送信元MACアドレス:{}, 宛先MACアドレス{}".format(src, dst))
        '''
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]  #Packet-Outするポートを指定
        else:
            out_port = ofproto.OFPP_FLOOD   #フラッディングさせるように設定
        actions = [parser.OFPActionOutput(out_port)]    #Actionの作成

        #再びパケットがPacket-Inしないようにフローエントリを設定
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)  #マッチ条件
            priority = 10   #優先度
            self.add_flow(datapath, priority, match, actions)
        
        #Packet-InされたパケットをPacket-outする
        data = msg.data 
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)  #Packet-Out