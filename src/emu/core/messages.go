package core

const (
	MSG_UPDATE_IPV4_ADDR   = "update_ipv4"   // client plugin, source ipv4 addr was changed (oldIpv4, NewIpv4 from type Ipv4Key )
	MSG_UPDATE_IPV6_ADDR   = "update_ipv6"   // client plugin, ipv6 addr was changed (oldIpv6, NewIpv6 from type Ipv6Key )
	MSG_UPDATE_DGIPV4_ADDR = "update_dgipv4" // client plugin, DG ipv4 addr was changed (oldIpv4, NewIpv4 from type Ipv4Key )
	MSG_UPDATE_DGIPV6_ADDR = "update_dgipv6" // client plugin, DG ipv4 addr was changed (oldIpv6, NewIpv6 from type Ipv6Key )
)
