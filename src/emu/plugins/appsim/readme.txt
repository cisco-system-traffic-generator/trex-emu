
+ add ioctl example 
- add profile in trex-core 
- add SDK docomentation 
- add emu doc 
- release it next version 


+ add ssdp example 
##################################
- test number appsim15 crash ... ? need to understand why 

+ fix the default ipv6.hop from 255 to 64 !!!
+ fix it to 255 first, 
sim30 
+ add emu_debug option 
+ add delay of 5 sec to the plugin (to settel ) or wait for event  to start !! look into the netflow plugin 
+ try to simulate udp  ( one side) with a few template and packets type. there is no need to simulate program as we have it already 
+ we can add RPC support and counters after that 

##################################

+ check that tid is valid
+ copy the server port from program 
+ add timer object per stream 
########

+ set the value from json 
+ add counters per client
+ add plugin tests (with UDP, no need for repeat TCP test ..)
 
 [{cps: type:[c:s] , tid:int}]
+ add RPC to add/remove/show ({cps: type:[c:s] , tid:int})
+ add RPC for counter show (pointer to the )

##################################

+ UDP/TCP/ipv4/ipv6 
+ delay/rand_delay, tx queue_full
+ loops of eflow (set val)
+ reset/close/connect/etc 
+ add keeplaive for udp 
+ check verification of json 


- add errors to the programs 
- add the real plugin tests 

- bug in case of dual close of flow FIN-ACK/FIN-ACK .. reppay  (transport)






