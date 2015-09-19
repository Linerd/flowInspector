#! /usr/bin/python

from scapy.all import *
from scapy.layers.inet import UDP, TCP, IP
from flow import Flow

class PacketIntervalTest(Automaton):
    #take five tuple (srcIP, dstIP, proto, sPort, dPort) as index
    #return a flow class
    flows = {}
    client_ip = '192.168.139.129'

    def master_filter(self, pkt):
        # return TCP in pkt or UDP in pkt and pkt[IP].src == self.client_ip or pkt[IP].dst == self.client_ip
        return TCP in pkt and (pkt[IP].src == self.client_ip or pkt[IP].dst == self.client_ip)
    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        print 'Begin\n'

        raise self.WAITING()

    # WAITING
    @ATMT.state()
    def WAITING(self):
        pass

    @ATMT.receive_condition(WAITING)
    def receive(self, pkt):
        if TCP in pkt:
            '''@TODO probably need to add more conditions'''
            raise self.RECEIVING_TCP(pkt)
        elif UDP in pkt:
            raise self.RECEIVING_UDP(pkt)

    '''@TODO will need a timeout to clear TCP flow cache'''
    @ATMT.timeout(WAITING, 10)
    def timeout_waiting(self):
        raise self.END()
    @ATMT.action(timeout_waiting)
    def echo_end(self):
        # self.send(self.last_packet)
        print '60s timeout! Ending...'

    # RECEIVED
    @ATMT.state()
    def RECEIVING_TCP(self, pkt):
        # print '*'*20
        # print pkt.time, pkt.sprintf("%-15s,IP.src% -> %-15s,IP.dst% %TCP.seq% %TCP.sport% -> %TCP.dport%")
        flow_tuple = (pkt[IP].src, pkt[IP].dst, pkt[IP].proto, pkt[TCP].sport, pkt[TCP].dport)
        if flow_tuple in self.flows:
            if pkt.src == self.client_ip:
                self.flows[flow_tuple].odd_add((pkt[TCP].seq, pkt.time))
            else:
                self.flows[flow_tuple].even_add((pkt[TCP].seq, pkt.time))
        else:
            f = Flow(*[flow_tuple[x] for x in range(5)])
            self.flows[flow_tuple] = f
            if pkt.src == self.client_ip:
                self.flows[flow_tuple].odd_add((pkt[TCP].seq, pkt.time))
            else:
                self.flows[flow_tuple].even_add((pkt[TCP].seq, pkt.time))

        # sendp(pkt, iface='eth1')
        raise self.WAITING()

    @ATMT.state()
    def RECEIVING_UDP(self, pkt):
        # print '*'*20
        print pkt.time, pkt.sprintf("%-15s,IP.src% -> %-15s,IP.dst% %IP.proto% %UDP.sport% -> %UDP.dport%")
        flow_tuple = (pkt[IP].src, pkt[IP].dst, pkt[IP].proto, pkt[UDP].sport, pkt[UDP].dport)
        if flow_tuple in self.flows:
            if pkt.src == self.client_ip:
                self.flows[flow_tuple].odd_add((pkt[UDP].seq, pkt.time))
            else:
                self.flows[flow_tuple].even_add((pkt[UDP].seq, pkt.time))
        else:
            f = Flow(*[flow_tuple[x] for x in range(5)])
            self.flows[flow_tuple] = f
            if pkt.src == self.client_ip:
                self.flows[flow_tuple].odd_add((pkt[UDP].seq, pkt.time))
            else:
                self.flows[flow_tuple].even_add((pkt[UDP].seq, pkt.time))

        # sendp(pkt, iface='eth1')
        raise self.WAITING()

    #END
    @ATMT.state(final=1)
    def END(self):
        keys = self.flows.viewkeys()
        for k in keys:
            print '*'*20
            # f = self.flows.get(k)
            # f.odd_printout()
            # f.even_printout()
            print k
        print 'End'

if __name__ == "__main__":
    a = PacketIntervalTest()
    a.run()
