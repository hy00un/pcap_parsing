## pcap_parsing

[gilgil's tutorial](https://gitlab.com/gilgil/network/wikis/ethernet-packet-dissection/pcap-programming)


sudo ip link add dum0 type dummy

ifconfig dum0 up

tcpreplay -i dum0 http.pcap


### result

![1](1.png)

### nslookup

![1](2.png)