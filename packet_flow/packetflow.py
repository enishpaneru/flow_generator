from scapy.all import *
from math import sqrt


class packetflow:
    def __init__(self, pkt: Packet):
        self.flow_id = self.gen_flow_id(pkt)
        self.src = pkt['IP'].src
        self.packetlist = [(pkt, True)]
        self.fw_pkts = 1
        self.bw_pkts = 0
        self.proto = pkt[1].proto
        self.duration = None
        self.total_len_f_pkts = 0
        self.total_len_b_pkts = 0

    def setduration(self):
        self.duration = int(round((self.packetlist[-1][0].time - self.packetlist[0][0].time)*1000000))

    def flow_direction(self, pkt):
        if str(pkt['IP'].src) == str(self.src):
            self.fw_pkts += 1
            return True
        else:
            self.bw_pkts += 1
            return False

    def packet_addition(self, pkt):
        fwd_dir = self.flow_direction(pkt)
        self.packetlist.append((pkt, fwd_dir))

    def gen_flow_id(self, pk: Packet):
        forward = True
        minlength = min(len(pk['IP'].src), len(pk['IP'].dst))
        for each in range(0, minlength):
            try:
                if pk['IP'].src[each] is not pk['IP'].dst[each]:
                    if pk['IP'].src[each] is '.':
                        forward = False
                        break
                    if pk['IP'].dst[each] is '.':
                        break
                    if int(pk['IP'].src[each]) > int(pk['IP'].dst[each]):
                        forward = False
                    break
            except Exception as e:
                print(pk['IP'].src, pk['IP'].dst)

        if (forward):
            flow_id = pk['IP'].src + "::" + pk['IP'].dst + "::" + str(pk['IP'].sport) + "::" + str(pk['IP'].dport)
        else:
            flow_id = pk['IP'].dst + "::" + pk['IP'].src + "::" + str(pk['IP'].dport) + "::" + str(pk['IP'].sport)
        return flow_id

    def same_proto_check(self):
        for each in self.packetlist:
            if each[1].proto != self.proto:
                return False

        return True

    def finalize_flow(self):
        self.setduration()

        for each in self.packetlist:
            if each[1] == True:
                try:
                    if each[0].haslayer('UDP'):
                        self.total_len_f_pkts += each[0][2].len - 8
                    else:
                        self.total_len_f_pkts += len(each[0][1].load)
                except:
                    pass
            else:
                try:
                    if each[0].haslayer('UDP'):
                        self.total_len_b_pkts += each[0][2].len - 8
                    else:
                        self.total_len_b_pkts += len(each[0][1].load)
                except:
                    pass  # the packets who throw exception are considered to have zero length

    def get_f_pkt_len_mean(self):
        return self.total_len_f_pkts / self.fw_pkts

    def get_b_pkt_len_min(self):
        min = 0
        for each in self.packetlist:
            if each[1] == False:
                try:
                    if each[0].haslayer('UDP'):
                        pkt_len = each[0][2].len - 8
                    else:
                        pkt_len = len(each[0][1].load)
                    if min == 0 or pkt_len < min:
                        min = pkt_len

                except Exception as e:
                    return 0
        return min

    def get_b_pkt_len_std(self):
        try:
            len_list = []
            for each in self.packetlist:
                if each[1] == False:
                    try:
                        if each[0].haslayer('UDP'):
                            len_list.append(each[0][2].len - 8)
                        else:
                            len_list.append(len(each[0][1].load))
                    except:
                        len_list.append(0)
            num_items = len(len_list)
            mean = sum(len_list) / num_items
            differences = [x - mean for x in len_list]
            sq_differences = [d ** 2 for d in differences]
            ssd = sum(sq_differences)
            variance = ssd / (num_items-1)
            sd = sqrt(variance)
            return sd
        except:
            return 0

    def get_f_pkt_per_s(self):
        return self.fw_pkts/self.duration *1000000

    def get_b_pkt_per_s(self):
        return self.bw_pkts/self.duration *1000000

    def get_flow_iat_mean_std_min(self):
        flow_iat=[]
        initial=self.packetlist[0][0].time
        for each in self.packetlist[1:]:
            flow_iat.append(round((each[0].time-initial)*1000000))
            initial=each[0].time
        mean= sum(flow_iat)/len(flow_iat)
        try:
            differences = [x - mean for x in flow_iat]
            sq_differences = [d ** 2 for d in differences]
            ssd = sum(sq_differences)
            variance = ssd / (len(flow_iat) - 1)
            sd = sqrt(variance)
        except:
            sd=0
        min=flow_iat[0]
        for each in flow_iat[1:]:
            if each<min:
                min=each
        return [mean,sd,min]

