#CSV stuff

import csv, os, glob, re
import sys

if len(sys.argv) != 2:
    print("Usage: python process_pcap.py <path_to_pcap_file>")
    sys.exit(1)

pcap_file_path = sys.argv[1]

class CSV():

    def __init__(self, file_name="file.csv", folder_name=""):

        self.file_name = file_name
        self.folder_name = folder_name
        self.current_file_name = ""
        self.rows = 0
        self.csv_w = None
        self.csv_r = None
        if(self.file_name.endswith(".csv") is True):
            pass
        else:
            self.file_name = self.file_name + ".csv"

        def create_folder(folder_name):
            if(self.folder_name != ""):
                if (os.path.exists(folder_name)):
                    pass
                else:
                    os.makedirs(folder_name)
            else:
                pass

        create_folder(self.folder_name)

    def create_empty_csv(self):
        file_name = self.file_name.replace(".csv", "")
        numbers = []
        if(self.folder_name == ""):
            pass
        else:
            file_name = self.folder_name + "/" + file_name
        for fn in glob(file_name + "*.csv"):
            val = re.findall('\d+', fn)
            if(len(val) == 0):
                pass
            else:
                numbers.append(int(val[0]))
        if(len(numbers) == 0):
            numbers.append(0)
        new_index = max(numbers) + 1
        file_name = file_name + "_" + str(new_index) + ".csv"
        self.csv_w = open(file_name, "a+")
        self.csv_r = open(file_name, "r")
        if(self.folder_name != ""):
            part_of_name = file_name.split("/")
            self.current_file_name = part_of_name[len(part_of_name)-1]
        else:
            self.current_file_name = file_name

    def add_row(self, row):
        csv_writer = csv.writer(self.csv_w, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(row)
        self.rows += 1

    def close_csv(self):
        if(self.csv_w is not None):
            self.csv_w.close()
        if(self.csv_r is not None):
            self.csv_r.close()

    def open_csv(self):
        file_name = self.get_file_path()
        try:
            self.csv_w = open(file_name, "a+")
            self.csv_r = open(file_name, "r")
        except Exception as e:
            print(e)
        if(self.csv_r is not None):
            try:
                csv_reader = csv.reader(self.csv_r, delimiter=",")
                self.rows = 0
                for row in csv_reader:
                    self.rows += 1
            except Exception as e:
                print(e)
        else:
            pass

    def get_number_of_rows(self, ignore_header=True):
        if(ignore_header is True):
            return self.rows - 1
        else:
            return self.rows
        
    def get_folder_name(self):
        return self.folder_name

    def get_current_file_name(self):
        return self.current_file_name

    def get_file_path(self):
        if(self.get_folder_name() == ""):
            return self.get_current_file_name()
        else:
            return self.get_folder_name() + "/" + self.get_current_file_name()

#Features Handler
import glob

class CreateFeaturesHandler():

    def __init__(self,pcap_file_path, pkts_window_size=10, single_csv=True):
        self.pcap_file_path = pcap_file_path
        self.pkts_window_size = pkts_window_size
        assert self.pkts_window_size >= 1, "Invalid value for the window size"
        self.single_csv = single_csv
        assert (self.single_csv is True) or (self.single_csv is False), "Invalid value for the single_csv flag"
        self.featuresCalc = FeaturesCalc(flow_type="malware", min_window_size=pkts_window_size)

        ip_to_ignore = ["0.0.0.0"] 
        # Can be used to filter Ips 
        # Can add more filters if required
        self.filter_1 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, TCP=True)
        self.filter_2 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, UDP=True)
        self.filter_3 = PacketFilter(ip_whitelist_filter=[], ip_blacklist_filter=ip_to_ignore, ICMP=True)
        self.filters = [self.filter_1, self.filter_2, self.filter_3]

        if self.single_csv:
            self.csv = CSV(file_name="features")
            self.csv.create_empty_csv()
            self.csv.add_row(self.featuresCalc.get_features_name())

    def compute_features(self):
        filter_res = []
        flow_type = "malware" #Doesnt matter because wont be using the Label value anymore
        if self.featuresCalc.get_flow_type() == flow_type:
            pass
        else:
            self.featuresCalc.set_flow_type(flow_type)
        if self.single_csv:
            csv = self.csv
        else:
            pcap_name = os.path.basename(self.pcap_file_path).replace(".pcap", "")
            csv = CSV(file_name=pcap_name, folder_name="Features")
            csv.create_empty_csv()
            csv.add_row(self.featuresCalc.get_features_name())
            
        pkts = rdpcap(self.pcap_file_path)
        array_of_pkts = []
        for pkt in pkts:
            for filter in self.filters:
                if filter.check_packet_filter(pkt):
                    filter_res.append(True)
                else:
                    filter_res.append(False)
            if True in filter_res:
                array_of_pkts.append(pkt)
            if len(array_of_pkts) >= self.featuresCalc.get_min_window_size():
                features = self.featuresCalc.compute_features(array_of_pkts)
                csv.add_row(features)
                array_of_pkts.clear()
            filter_res.clear()
        
        return csv.get_file_path()

#Features Calc

import os
import statistics
from scapy.all import *

class FeaturesCalc():

    malware_label = 1.0
    legitimate_label = 0.0

    def __init__(self, flow_type, min_window_size=2):
        self.flow_type = flow_type
        self.min_window_size = int(min_window_size)
        assert self.flow_type == "malware" or self.flow_type == "legitimate", "Invalid flow_type. Valid values are malware or legitimate."
        assert self.min_window_size > 0, "Invalid value for min_window_size. Must be greater than 0."
        self.label = None
        if self.flow_type == "malware":
            self.label = self.malware_label
        else:
            self.label = self.legitimate_label

        self.features_name = ["Avg_syn_flag", "Avg_urg_flag", "Avg_fin_flag", "Avg_ack_flag", "Avg_psh_flag", "Avg_rst_flag", "Avg_DNS_pkt", "Avg_TCP_pkt",
                      "Avg_UDP_pkt", "Avg_ICMP_pkt", "Duration_window_flow", "Avg_delta_time", "Min_delta_time", "Max_delta_time", "StDev_delta_time",
                      "Avg_pkts_length", "Min_pkts_length", "Max_pkts_length", "StDev_pkts_length", "Avg_small_payload_pkt", "Avg_payload", "Min_payload",
                      "Max_payload", "StDev_payload", "Avg_DNS_over_TCP", "Src_IP", "Dst_IP", "Label"]


        self.total_packets = 0
        self.nb_samples = 0

    def compute_features(self, packets_list):

        def increment_sample_nb(nb):
            self.nb_samples += nb

        def update_received_pkts(nb):
            self.total_packets += nb

        def compute_avg(list_of_values):
            if len(list_of_values) == 0:
                return 0.0
            else:
                return float(sum(list_of_values) / self.get_min_window_size())

        def compute_min(list_of_values):
            if len(list_of_values) == 0:
                return 0.0
            else:
                return float(min(list_of_values))

        def compute_max(list_of_values):
            if len(list_of_values) == 0:
                return 0.0
            else:
                return float(max(list_of_values))

        def compute_stDev(list_of_values):
            if len(list_of_values) == 0 or len(list_of_values) == 1:
                return 0.0
            else:
                try:
                    stat = statistics.stdev(list_of_values)
                    return float(stat)
                except:
                    return 0.0

        def DNS_over_TCP_ratio(packets_list):
            total_DNS = float(sum(compute_DNS_packets(packets_list)))
            ratio_list = []
            total_packet_high_level_list = []
            list_of_pkt_with_TCP = compute_TCP_packets(packets_list)
            list_of_paylod_length = compute_packet_TCP_payload_size(packets_list, count_packet_without_payload=True)

            if len(packets_list) == len(list_of_pkt_with_TCP) and len(packets_list) == len(list_of_paylod_length):
                for i in range(0, len(packets_list) - 1):
                    if list_of_pkt_with_TCP[i] == 1.0:
                        if list_of_paylod_length[i] > 0:
                            if not packets_list[i].haslayer("DNS"):
                                total_packet_high_level_list.append(1.0)
                            else:
                                total_packet_high_level_list.append(0.0)
                        else:
                            total_packet_high_level_list.append(0.0)
                    else:
                        total_packet_high_level_list.append(0.0)
            else:
                print("Unexpected error in DNS_over_TCP_ratio()")

            total_packet_high_level = float(sum(total_packet_high_level_list))
            if total_packet_high_level != 0:
                ratio_list.append(float(total_DNS / total_packet_high_level))
            else:
                ratio_list.append(0.0)

            i = 1
            while i <= len(packets_list) - 1:
                ratio_list.append(0.0)
                i += 1

            return ratio_list

        def compute_duration_flow(packets_list):
            return packets_list[len(packets_list) - 1].time - packets_list[0].time

        def packets_bytes_length(packets_list):
            pkt_length_list = []
            for pkt in packets_list:
                pkt_length_list.append(float(len(pkt)))
            return pkt_length_list

        def compute_DNS_packets(packets_list):
            dns_counter = []
            for pkt in packets_list:
                if pkt.haslayer("DNS"):
                    dns_counter.append(1.0)
                else:
                    dns_counter.append(0.0)
            return dns_counter

        def compute_TCP_packets(packets_list):
            tcp_counter = []
            for pkt in packets_list:
                if pkt.haslayer("TCP"):
                    tcp_counter.append(1.0)
                else:
                    tcp_counter.append(0.0)
            return tcp_counter

        def compute_UDP_packets(packets_list):
            udp_counter = []
            for pkt in packets_list:
                if pkt.haslayer("UDP"):
                    udp_counter.append(1.0)
                else:
                    udp_counter.append(0.0)
            return udp_counter

        def compute_ICMP_packets(packets_list):
            icmp_counter = []
            for pkt in packets_list:
                if pkt.haslayer("ICMP") is True:
                    icmp_counter.append(1.0)
                else:
                    icmp_counter.append(0.0)
            return icmp_counter

        def compute_packet_with_small_TCP_payload(packets_list, count_packet_without_payload=False):
            packets_small_payload_count = []
            pkt_payload_list = compute_packet_TCP_payload_size(packets_list, count_packet_without_payload=count_packet_without_payload)
            for payload in pkt_payload_list:
                if payload <= 32:
                    packets_small_payload_count.append(1.0)
                elif payload > 32:
                    packets_small_payload_count.append(0.0)
                elif payload is None:
                    if count_packet_without_payload:
                        packets_small_payload_count.append(0.0)
                    else:
                        pass
            return packets_small_payload_count

        def compute_packet_TCP_payload_size(packets_list, count_packet_without_payload=False):
            payload_size_list = []
            for pkt in packets_list:
                if pkt.haslayer("TCP"):
                    if pkt["TCP"].payload is None:
                        payload_size_list.append(0.0)
                    else:
                        payload_size_list.append(float(len(pkt["TCP"].payload)))
                else:
                    if count_packet_without_payload:
                        payload_size_list.append(None)
                    else:
                        pass
            return payload_size_list

        def compute_delta_time(packets_list):
            i = 1
            delta_time_list = []
            while i <= (len(packets_list) - 1):
                delta_time_list.append(packets_list[i].time - packets_list[i - 1].time)
                i += 1
            return delta_time_list

        def compute_tcp_flags(packets_list):
            syn_counter = []
            fin_counter = []
            ack_counter = []
            psh_counter = []
            urg_counter = []
            rst_counter = []
            FIN = 0x01
            SYN = 0x02
            RST = 0x04
            PSH = 0x08
            ACK = 0x10
            URG = 0x20
            for pkt in packets_list:
                if pkt.haslayer("TCP"):
                    F = pkt["TCP"].flags
                    if F & FIN:
                        fin_counter.append(1.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & SYN:
                        fin_counter.append(0.0)
                        syn_counter.append(1.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & RST:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(1.0)
                    elif F & PSH:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(1.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & ACK:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(1.0)
                        psh_counter.append(0.0)
                        urg_counter.append(0.0)
                        rst_counter.append(0.0)
                    elif F & URG:
                        fin_counter.append(0.0)
                        syn_counter.append(0.0)
                        ack_counter.append(0.0)
                        psh_counter.append(0.0)
                        urg_counter.append(1.0)
                        rst_counter.append(0.0)
                    else:
                        pass
                else:
                    fin_counter.append(0.0)
                    syn_counter.append(0.0)
                    ack_counter.append(0.0)
                    psh_counter.append(0.0)
                    urg_counter.append(0.0)
                    rst_counter.append(0.0)
            return syn_counter, fin_counter, ack_counter, psh_counter, urg_counter, rst_counter

        if len(packets_list) < self.get_min_window_size():
            print("\nNumber of packets too low\n")
            return None
        else:
            syn_lst, fin_lst, ack_lst, psh_lst, urg_lst, rst_lst = compute_tcp_flags(packets_list)
            syn_avg = compute_avg(syn_lst)
            fin_avg = compute_avg(fin_lst)
            ack_avg = compute_avg(ack_lst)
            psh_avg = compute_avg(psh_lst)
            urg_avg = compute_avg(urg_lst)
            rst_avg = compute_avg(rst_lst)

            duration_flow = compute_duration_flow(packets_list)
            avg_time_flow = compute_avg(compute_delta_time(packets_list))
            min_time_flow = compute_min(compute_delta_time(packets_list))
            max_time_flow = compute_max(compute_delta_time(packets_list))
            stdev_time_flow = compute_stDev(compute_delta_time(packets_list))
            dns_pkt = compute_avg(compute_DNS_packets(packets_list))
            tcp_pkt = compute_avg(compute_TCP_packets(packets_list))
            udp_pkt = compute_avg(compute_UDP_packets(packets_list))
            icmp_pkt = compute_avg(compute_ICMP_packets(packets_list))
            pkt_length_avg = compute_avg(packets_bytes_length(packets_list))
            pkt_length_min = compute_min(packets_bytes_length(packets_list))
            pkt_length_max = compute_max(packets_bytes_length(packets_list))
            pkt_length_stdev = compute_stDev(packets_bytes_length(packets_list))
            small_pkt_payload_avg = compute_avg(compute_packet_with_small_TCP_payload(packets_list, False))
            avg_payload = compute_avg(compute_packet_TCP_payload_size(packets_list, False))
            min_payload = compute_min(compute_packet_TCP_payload_size(packets_list, False))
            max_payload = compute_max(compute_packet_TCP_payload_size(packets_list, False))
            stdev_payload = compute_stDev(compute_packet_TCP_payload_size(packets_list, False))
            dns_over_tcp_ratio_normalized = compute_avg(DNS_over_TCP_ratio(packets_list))
            first_pkt = packets_list[0]
            if first_pkt.haslayer("IP"):
                src_ip = first_pkt["IP"].src
                dst_ip = first_pkt["IP"].dst
            else:
                src_ip = "No_IP"
                dst_ip = "No_IP"

            row = [syn_avg, urg_avg, fin_avg, ack_avg, psh_avg, rst_avg, dns_pkt, tcp_pkt, udp_pkt, icmp_pkt, duration_flow, avg_time_flow,
                min_time_flow, max_time_flow, stdev_time_flow, pkt_length_avg, pkt_length_min, pkt_length_max, pkt_length_stdev,
                small_pkt_payload_avg, avg_payload, min_payload, max_payload, stdev_payload, dns_over_tcp_ratio_normalized, src_ip, dst_ip, self.label]

            increment_sample_nb(1)
            update_received_pkts(len(packets_list))
            return row

    def get_total_pkts(self):
        return self.total_packets

    def get_total_sample(self):
        return self.nb_samples

    def reset_sample_counter(self):
        self.nb_samples = 0

    def reset_total_pkts_counter(self):
        self.total_packets = 0

    def set_min_window_size(self, val):
        self.min_window_size = val

    def get_min_window_size(self):
        return self.min_window_size

    def set_flow_type(self, flow_type):
        assert self.flow_type == "malware" or self.flow_type == "legitimate", "Invalid flow_type. Valid values are malware or legitimate."
        self.flow_type = flow_type
        if self.flow_type == "malware":
            self.label = self.malware_label
        else:
            self.label = self.legitimate_label

    def get_flow_type(self):
        return self.flow_type

    def get_features_name(self):
        return self.features_name

#Packet Filter


class PacketFilter():

    def __init__(self, ip_whitelist_filter=[], ip_blacklist_filter=[], IPv4=False, TCP=False, UDP=False, ICMP=False, DNS=False):
        self.ip_whitelist_filter = ip_whitelist_filter
        self.ip_blacklist_filter = ip_blacklist_filter
        self.IPv4 = IPv4
        self.TCP = TCP
        self.UDP = UDP
        self.ICMP = ICMP
        self.DNS = DNS
        filters = [self.IPv4, self.TCP, self.UDP, self.ICMP, self.DNS]
        assert sum(filters) <= 1, "You have to set just one protocol filter."
        if(len(self.ip_whitelist_filter) > 0 or len(self.ip_blacklist_filter) > 0):
            self.set_IPv4_filter(True)

    def check_packet_filter(self, pkt):

        results = []

        def IPv4_filter(pkt):
            if(pkt.haslayer("IP")):
                return True
            else:
                return False

        def ip_blacklist_filter(pkt, check_list):
            if(IPv4_filter(pkt) is True):
                if(len(check_list) > 0):
                    if(pkt["IP"].src not in check_list):
                        return True
                    else:
                        return False
                else:
                    return True
            else:
                return False

        def ip_whitelist_filter(pkt, check_list):
            if(IPv4_filter(pkt) is True):
                if(len(check_list) > 0):
                    if(pkt["IP"].src in check_list):
                        return True
                    else:
                        return False
                else:
                    return True
            else:
                return False

        def UDP_filter(pkt):
            if(pkt.haslayer("UDP")):
                return True
            else:
                return False

        def TCP_filter(pkt):
            if(pkt.haslayer("TCP")):
                return True
            else:
                return False

        def DNS_filter(pkt):
            if(pkt.haslayer("DNS")):
                return True
            else:
                return False

        def ICMP_filter(pkt):
            if(pkt.haslayer("ICMP")):
                return True
            else:
                return False

        if(self.get_IPv4_filter() is True):
            res = IPv4_filter(pkt)
            results.append(res)
        if(len(self.get_ip_blacklist_filter()) > 0):
            res =  ip_blacklist_filter(pkt, self.get_ip_blacklist_filter())
            results.append(res)
        if(len(self.get_ip_whitelist_filter()) > 0):
            res = ip_whitelist_filter(pkt, self.get_ip_whitelist_filter())
            results.append(res)
        if(self.get_TCP_filter() is True):
            res = TCP_filter(pkt)
            results.append(res)
        if(self.get_UDP_filter() is True):
            res = UDP_filter(pkt)
            results.append(res)
        if(self.get_ICMP_filter() is True):
            res = ICMP_filter(pkt)
            results.append(res)
        if(self.get_DNS_filter() is True):
            res = DNS_filter(pkt)
            results.append(res)
        if(False in results):
            return False
        else:
            return True


    def set_IPv4_filter(self, val):
        self.IPv4 = val

    def set_ip_whitelist_filter(self, ip_filter):
        self.ip_whitelist_filter = ip_filter

    def set_ip_blacklist_filter(self, ip_filter):
        self.ip_blacklist_filter = ip_filter

    def set_TCP_filter(self, val):
        self.TCP = val

    def set_UDP_filter(self, val):
        self.UDP = val

    def get_TCP_filter(self):
        return self.TCP

    def get_UDP_filter(self):
        return self.UDP

    def get_IPv4_filter(self):
        return self.IPv4

    def set_ICMP_filter(self, val):
        self.ICMP = val

    def get_ICMP_filter(self):
        return self.ICMP

    def set_DNS_filter(self, val):
        self.DNS = val

    def get_DNS_filter(self):
        return self.DNS

    def get_ip_whitelist_filter(self):
        return self.ip_whitelist_filter

    def get_ip_blacklist_filter(self):
        return self.ip_blacklist_filter
    
if __name__ == "__main__":
    cfh = CreateFeaturesHandler(pcap_file_path, single_csv=True)
    csv_file_path = cfh.compute_features()
    print(csv_file_path)  # This is to be captured by subprocess.run in app.py

