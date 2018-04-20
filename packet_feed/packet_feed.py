import subprocess
from scapy.all import *
import glob

from packet_flow.packetflow import packetflow


class packet_feed:
    def __init__(self):

        # subprocess.call(["ifconfig", "wlp6s0", "promisc"], stdout=None, stderr=None, shell=False)#shell=True for windows
        self.connection_list = {}
        self.timeout = 120
        self.numbercount = 2

    def feed_func(self, pkt: Packet):

        try:
            print(pkt.summary())
            if pkt.haslayer('IP') and ( pkt.haslayer('TCP') or pkt.haslayer('UDP')):
                flow = packetflow(pkt)

                if flow.flow_id in self.connection_list:

                    if (pkt.time - self.connection_list[flow.flow_id].packetlist[0][0].time) > self.timeout:

                        self.connection_list[flow.flow_id].finalize_flow()

                        self.print_output(self.connection_list[flow.flow_id])
                        self.connection_list[flow.flow_id] = flow
                    else:
                        self.connection_list[flow.flow_id].packet_addition(pkt)
                        if pkt.haslayer('TCP'):
                            if 'F' in str(pkt['TCP'].flags) or pkt['TCP'].flags & 0x01:
                                self.connection_list[flow.flow_id].finalize_flow()
                                self.print_output(self.connection_list[flow.flow_id])
                                del self.connection_list[flow.flow_id]

                else:
                    self.connection_list[flow.flow_id] = flow

        except Exception as e:
            print('Exception ', e)

    def read_pcap(self):
        for each in glob.glob('pcaps/*.pcap'):
            pkreader = PcapReader(each)
            for pkt in pkreader:
                self.feed_func(pkt)

    def sniff_pkt(self):
        pkt = sniff(iface="wlp6s0", prn=self.feed_func)

    def print_output(self, flow:packetflow):
        print('****')
        # print(flow.same_proto_check())
        # print(flow.proto)
        # print(flow.flow_id)
        # print(flow.fw_pkts)
        # print(flow.bw_pkts)
        # print(flow.duration)
        # print(flow.total_len_f_pkts)
        # print(flow.total_len_b_pkts)
        # print(flow.get_f_pkt_len_mean())
        # print(flow.get_b_pkt_len_min())
        # print(flow.get_b_pkt_len_std())
        # print(flow.get_f_pkt_per_s())
        # print(flow.get_b_pkt_per_s())
        print(flow.get_flow_iat_mean_std_min())
        print('****')
