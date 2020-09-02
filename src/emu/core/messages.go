package core

const (
	RESOLVED_IPV4_DG_MAC = 1 << iota // Flag to indicate the IPv4 default gateway mac was resolved
	RESOLVED_IPV6_DG_MAC             // Flag to indicate the IPv6 default gateway mac was resolved
)

const (
	MSG_UPDATE_IPV4_ADDR   = "update_ipv4"     // client plugin, source ipv4 addr was changed (oldIpv4, NewIpv4 from type Ipv4Key )
	MSG_UPDATE_IPV6_ADDR   = "update_ipv6"     // client plugin, ipv6 addr was changed (oldIpv6, NewIpv6 from type Ipv6Key )
	MSG_UPDATE_DIPV6_ADDR  = "update_dipv6"    // client plugin, ipv6 addr was changed (oldIpv6, NewIpv6 from type Ipv6Key )
	MSG_UPDATE_DGIPV4_ADDR = "update_dgipv4"   // client plugin, DG ipv4 addr was changed (oldIpv4, NewIpv4 from type Ipv4Key )
	MSG_UPDATE_DGIPV6_ADDR = "update_dgipv6"   // client plugin, DG ipv4 addr was changed (oldIpv6, NewIpv6 from type Ipv6Key )
	MSG_DG_MAC_RESOLVED    = "dg_mac_resolved" // client plugin, DG MAC was resolved. When sending this message, the first broadcast parameter `a` is a bit mask of the previous flags.
)
