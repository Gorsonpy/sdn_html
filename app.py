import numpy as np
import mmh3
import random
import logging
import traceback
from math import log, e, ceil
from flask import Flask, jsonify, abort, render_template, redirect
from scapy.all import Ether, IP, TCP, UDP, sendp, sniff
from scapy.packet import NoPayload
import string
import json
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.log import setLogLevel
#from flask_cors import CORS
import threading
import subprocess


app = Flask(__name__)

net = None
net_lock = threading.Lock()

class MyTopo(Topo):
    def __init__(self):
        super(MyTopo, self).__init__()

        c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
        #c0 = self.addController(name='c0',controller=RemoteController,protocol='tcp',p='127.0.0.1',port=6633)
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch)

        h2 = self.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
        h1 = self.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
        h3 = self.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
        h4 = self.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h3)
        self.addLink(s2, h4)

        self.mininet = Mininet(topo=self, build=False, ipBase='10.0.0.0/8')
        net = self.mininet
        self.mininet.controllers = [c0]
        self.mininet.build()
        self.mininet.start()

@app.route('/makeTopology',methods=['GET','POST'])
def setup_topology():
    global net

    with net_lock:
        if net is None:
            try:
                topo = MyTopo()
                net = topo.mininet
                control = net.addController(name='c0', controller=RemoteController, protocol='tcp', p='127.0.0.1', port=6633)
                CLI(net)
                return json.dumps({"code": 200, "msg": "ok"})
            except Exception as e:
                traceback.print_exc()
                error_msg = str(e)
                return json.dumps({"code": 500, "msg": error_msg})
        else:
            return json.dumps({"code": 500, "msg": "Topology already exists"})

@app.route('/packetGen', methods=['POST', 'GET'])
def send_packets():
    result = {}
    type = ' '
    # 随机生成长度为length的字符串
    def generate_random_string(length):
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for i in range(length))

    # 发送数据包
    def send_packet(src_ip, dst_ip, src_port, dst_port, content):
        eth = Ether()
        ip = IP(src=src_ip, dst=dst_ip)
        tcp = TCP(sport=src_port, dport=dst_port)
        udp = UDP(sport=src_port, dport=dst_port)
        packet_1 = eth / ip / tcp / content
        packet_2 = eth / ip / udp / content
        num = random.randint(1, 2)
        if num == 1:
            type='TCP'
            print(type)
            sendp(packet_1)
        else:
            type = 'UDP'
            print(type)
            sendp(packet_2)
        print(f"构造数据包：从 {src_ip}:{src_port} 发送到 {dst_ip}:{dst_port}")
        return type
    host_list = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
    port_list = [6001, 6002, 6003, 6004]

    content = generate_random_string(random.randint(10, 20))

    # 从主机列表中随机选择源主机和目的主机
    source_host, destination_host = random.sample(host_list, 2)

    # 获取所选主机对应的端口号
    source_port = port_list[host_list.index(source_host)]
    destination_port = port_list[host_list.index(destination_host)]

    try:
        type=send_packet(source_host, destination_host, source_port, destination_port, content)
        result["sourceIp"] = source_host
        result["dstIp"] = destination_host
        result["sourcePort"] = source_port
        result["dstPort"] = destination_port
        result["code"] = 200
        result["data"] = content
        result["type"] = type
        result["msg"] = 'ok'
        return json.dumps(result)
    except Exception as e:
        result["code"] = 500
        result["msg"] = str(e)
        return json.dumps(result)

@app.route('/trafficAnalysis', methods=['POST', 'GET'])
def TOPO_K():
    try:
#k = 5
        k=int(request.args.get('k'))
        print(k)
        result = Find_K(k)
        print(2222)
        return jsonify({"topStreams": result, "msg": "Processed k value successfully.", "code": 200})
    except Exception as e:
        return jsonify({"error": "An error occurred while processing k value.", "code": 500})


def Find_K(k):
    packets = []
    for i in range(20):
        captured_packets = sniff(filter="ip", count=1)
        packets.extend(captured_packets)
    print(packets)
    streams = [(packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, packet[IP].proto) for packet in
               packets]
    counter = Counter(streams)
    top_k_streams = counter.most_common(k)

    result = []
    for stream, count in top_k_streams:
        if stream[4] == 6:  # TCP协议
            result.append({
                "sourceIp": stream[0],
                "sourcePort": stream[1],
                "dstIp": stream[2],
                "dstPort": stream[3],
                "type": "TCP",
                "occur": count
            })
        elif stream[4] == 17:  # UDP协议
            result.append({
                "sourceIp": stream[0],
                "sourcePort": stream[1],
                "dstIp": stream[2],
                "dstPort": stream[3],
                "type": "UDP",
                "occur": count
            })
    print(result)
    return result

@app.route('/trafficStatics', methods=['GET', 'POST'])
def get_data():
    output = run_count_min_sketch()
    return jsonify(output)


# CM-Sketch
class CountMinSketch:
    def __init__(self, epsilon, delta):
        self.epsilon = epsilon
        self.delta = delta
        self.width = int(ceil(e / epsilon))
        self.depth = int(ceil(log(1. / delta)))
        self.sketch = np.zeros((self.depth, self.width))

    def update(self, packet):
        for i in range(self.depth):
            index = mmh3.hash128(
                str(packet[0]) + str(packet[1]) + str(packet[2]) + str(packet[3]) + str(packet[4])) % self.width
            self.sketch[i][index] += 1

    def estimate(self, packet):
        index = mmh3.hash128(
            str(packet[0]) + str(packet[1]) + str(packet[2]) + str(packet[3]) + str(packet[4])) % self.width
        return min(self.sketch[i][index] for i in range(self.depth))

def run_count_min_sketch():
    try:
        epsilon = 0.00001
        delta = 0.01
        cms = CountMinSketch(epsilon, delta)
        new_address_list = []
        address_list = []
        def packet_handler(packet):
            if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
                ip_layer = packet.getlayer('IP')
                if 'TCP' in packet:
                    tcp_layer = packet.getlayer('TCP')
                    payload = str(tcp_layer.payload)
                    address_list.append((ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport, 'TCP', payload))
                if 'UDP' in packet:
                    udp_layer = packet.getlayer('UDP')
                    payload = str(udp_layer.payload)
                    address_list.append((ip_layer.src, ip_layer.dst, udp_layer.sport, udp_layer.dport, 'UDP', payload))

        sniff(filter="ip", prn=packet_handler, count=20)

        result = []
        for address in address_list:
            cms.update(address)
        new_address_list = remove_duplicates(address_list)
        print(new_address_list)
        for address in new_address_list:
            count = cms.estimate(address)
            print(count)
            result.append({
                "sourceIp": address[0],
                "dstIp": address[1],
                "sourcePort": address[2],
                "dstPort": address[3],
                "type": address[4],
                "msg": address[5],
                "occur": count
            })

        logging.info("Data processing and estimation completed successfully.")
        return {"result": result, "message": "Data processing and estimation completed successfully.", "code": 200}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {"result": result, "error": f"An error occurred: {str(e)}", "code": 500}


def has_duplicate(lst):
    count = {}
    for item in lst:
        count[item] = count.get(item, 0) + 1
        if count[item] > 1:
            return True
    return False


def remove_duplicates(lst):
    if has_duplicate(lst):
        seen = set()
        result = []
        for item in lst:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result
    else:
        return lst
if __name__ == '__main__':
    app.run(port=6688,debug=True)
