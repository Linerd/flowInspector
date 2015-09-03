# flowInspector
Inter-packet latencies can reveal network condition along the way from UE to internet. If we put host processing latency aside, which in most cases should not be the biggest concern, a larger packet-interval usually means a poorer network condition, probably due to congestion or limited bandwidth. The trend of the interval changes can also indicate jitterness.
We're using scapy to observe tcp flows that pass by the container, measure and record the packet-intervals. It is possible that we can introduce packet buffering and ad-injection service based on this tool we build.
