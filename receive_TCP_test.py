from scapy.all import *
from scapy.layers.inet import IP, TCP


class TCPTest(Automaton):
    # def parse_args(self, filename, server, sport = None, port=69, **kargs):
    #     Automaton.parse_args(self, **kargs)
    #     # self.filename = filename
    #     # self.server = server
    #     # self.port = port
    #     # self.sport = sport

    def master_filter(self, pkt):
        return IP in pkt

    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        print 'Begin\n'
        # self.blocksize=512
        # self.my_tid = self.sport or RandShort()._fix()
        # bind_bottom_up(UDP, TFTP, dport=self.my_tid)
        # self.server_tid = None
        # self.res = ""
        #
        # self.l3 = IP(dst=self.server)/UDP(sport=self.my_tid, dport=self.port)/TFTP()
        # self.last_packet = self.l3/TFTP_RRQ(filename=self.filename, mode="octet")
        # self.send(self.last_packet)
        # self.awaiting=1

        raise self.WAITING()

    # WAITING
    @ATMT.state()
    def WAITING(self):
        print 'Waiting\n'
        pass

    @ATMT.receive_condition(WAITING)
    def receive_tcp(self, pkt):
        # if TFTP_DATA in pkt and pkt[TFTP_DATA].block == self.awaiting:
        #     if self.server_tid is None:
        #         self.server_tid = pkt[UDP].sport
        #         self.l3[UDP].dport = self.server_tid
        if TCP in pkt:
            '''@TODO probably need to add more conditions'''
            raise self.RECEIVING(pkt)

    #@ATMT.action(receive_tcp)
    #def packet_show(self):

    # def send_ack(self):
    #     self.last_packet = sel0f.l3 / TFTP_ACK(block = self.awaiting)
    #     self.send(self.last_packet)

    '''@TODO don't consider errors for now'''
    # @ATMT.receive_condition(WAITING, prio=1)
    # def receive_error(self, pkt):
    #     if TFTP_ERROR in pkt:
    #         raise self.ERROR(pkt)

    '''@TODO will need a timeout to clear TCP flow cache'''
    @ATMT.timeout(WAITING, 60)
    def timeout_waiting(self):
        raise self.END()
    @ATMT.action(timeout_waiting)
    def echo_end(self):
        # self.send(self.last_packet)
        print '60s timeout! Ending...'

    # RECEIVED
    @ATMT.state()
    def RECEIVING(self, pkt):
        # recvd = pkt[Raw].load
        # self.res += recvd
        # self.awaiting += 1
        # if len(recvd) == self.blocksize:
        #     raise self.WAITING()
        pkt.show()
        raise self.WAITING()

    # ERROR
    # @ATMT.state(error=1)
    # def ERROR(self,pkt):
    #     split_bottom_up(UDP, TFTP, dport=self.my_tid)
    #     return pkt[TFTP_ERROR].summary()

    #END
    @ATMT.state(final=1)
    def END(self):
        print 'End'
        # split_bottom_up(UDP, TFTP, dport=self.my_tid)
        # return self.res