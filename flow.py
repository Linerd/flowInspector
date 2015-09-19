class Flow(object):

    def __init__(self):
        self.__init__('', '', -1, -1, -1)

    def __init__(self, src, dst, proto, sport, dport):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.odd_timestamps = list()
        self.even_timestamps = list()

    def odd_add(self, ts):
        self.odd_timestamps.append(ts)

    def even_add(self, ts):
        self.even_timestamps.append(ts)

    def odd_printout(self):
        for ts in self.odd_timestamps:
            print ts, '\n'

    def even_printout(self):
        for ts in self.even_timestamps:
            print ts, '\n'
