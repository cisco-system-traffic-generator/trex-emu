2) fix zmq 
1) fix this 
		eap.Id, uint8(layers.EAPTypeNACK),
		[]byte{EAP_TYPE_MSCHAPV2})

dot1x system-auth-control
dot1x eapol version 2
dot1x logging verbose


radius server hhaim-lap
 address ipv4 10.56.99.210 auth-port 1812 acct-port 1813
 key switch1
!
interface GigabitEthernet2/0/21
 switchport access vlan 2000
 switchport mode access
 authentication timer reauthenticate 1
 access-session host-mode single-host
 access-session control-direction in
 access-session port-control auto
 dot1x pae authenticator
 dot1x timeout quiet-period 1
 dot1x timeout server-timeout 1
 dot1x timeout tx-period 1
 dot1x timeout start-period 1
 dot1x timeout held-period 1
 dot1x timeout auth-period 1
 spanning-tree portfast
 service-policy type control subscriber DOT1X-1

policy-map type control subscriber DOT1X-1
 event session-started match-all
  10 class always do-all
   10 authenticate using dot1x priority 10

aaa group server radius lap1
 server name hhaim-lap
!
aaa authentication dot1x default group lap1

nmap -sU -PN -p 1810-1812 127.0.0.1


###########
PORT forwarding of 1812 to remote radius 
UDP port forwarding
###########

radius(s1)          [ lab L1  ]

1) from remote radius(s1) 
ssh -R 5000:localhost:5000 L1

2) in lab L1 
side: socat -T15 udp4-recvfrom:1812,reuseaddr,fork tcp:12.0.0.1:5000

3) in S1 socat tcp4-listen:5000,reuseaddr,fork UDP:127.0.0.1:1812




