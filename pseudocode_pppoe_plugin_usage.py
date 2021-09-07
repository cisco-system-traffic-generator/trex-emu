# Copyright (c) 2021 Eolo S.p.A. and Altran Italia S.p.A. and/or them affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# that can be found in the LICENSE file in the root of the source
# tree.

# Code described into this file is to be intended as example of TRex EMU PPP plugin usage flow.

####
#### Omitted import section
####

nr_of_clients = config.getint("PPP Access", "nr_of_clients")
max_clients_port = config.getint("PPP Access", "max_clients_port")
customer_vlan = config.getint("PPP Access", "vlan_customer", fallback = None)

ppp_port_id = config.getint("PPP Access", "TRex PPP Port Id")
# ppp client mac addresses list
mac_list = []
# ppp client userid for Pap auth
ppp_users = []

for index in range(0, nr_of_clients):
    mac_last_byte = index % max_clients_port
    if mac_last_byte == 0:
        dut_ppp_port_id = dut_ppp_port_id + 1
    mac_list.append("02:00:00:%02x:00:%02x" % (dut_ppp_port_id, mac_last_byte))

####
#### Create TRex clients objects
####

trex_host = config.get("TRex", "hostname")
trex_async_port = config.get("TRex", "trex_async_port")
trex_sync_port = config.get("TRex", "trex_sync_port")
trex_emu_port = config.get("TRex", "trex_emu_port", fallback = None)

trex_client = STLClient( server = trex_host,
            async_port = trex_async_port,
            sync_port = trex_sync_port,
            verbose_level = "info")

trex_client.connect()

emu_client = None
if trex_emu_port:
    # Creation of EMU client obj
    emu_client = EMUClient(
                server = trex_host,
                sync_port = trex_emu_port,
                verbose_level = "info",
                logger = None,
                sync_timeout = 60)

    emu_client.connect()

trex_client.acquire(force = True)
trex_client.reset()
trex_client.set_port_attr(promiscuous = True, link_up = True)

####
#### Create TRex clients objects - END
####

####
#### Emulate PPP Clients
####

# returned dict Mac (string) -> (serverMac, sessionId, assignedIP)
ans_dict = {}
# mapping dict Mac (string) -> EMUClientKey
mac2key = {}

### Creation of NS key with VLAN for Clients
ns_key = EMUNamespaceKey(vport = ppp_port_id, tci = customer_vlan) if customer_vlan else EMUNamespaceKey(vport = ppp_port_id)

### NS obj use key and default plugs dict
ppp_ns = EMUNamespaceObj(
    ns_key = ns_key,
    def_c_plugs = {
        'ppp': {}
    }
)

mac2user_dict = {}
if ppp_users and len(ppp_users) > 0:
    #### data check based on length
    data_check = len(ppp_users) == len(mac_addresses)
    dc_err_msg = "Mismatch input data MAC Addresses (%d) and PPP Users (%d)!" % (len(mac_addresses), len(ppp_users))
    assert data_check, dc_err_msg
    #### data check based on length - END
    for single_mac, single_user in zip(mac_addresses, ppp_users):
        mac2user_dict[single_mac] = single_user
else:
    for single_mac in mac_addresses:
        mac2user_dict[single_mac] = "password" + single_mac.replace(':','')

for single_mac, single_user in mac2user_dict.items():
    ### Creation of UserID based on mac
    ppp_dict = {
        'user': single_user,
        'password': 'test',
        'timeout': 10
    }

    client_dict = {}
    client_dict['ppp'] = ppp_dict

    mac4emu = Mac(single_mac)

    ### Creation of EMU Client obj
    clientObj = EMUClientObj(
        mac = mac4emu.V(),
        plugs = client_dict)
    ### Add EMU Client to NS
    ppp_ns.add_clients(clientObj)
    ### Add EMU Client to local array in manner to handle script logic with iteration
    mac2key[single_mac] = EMUClientKey(ns_key, mac4emu.V())
    ### Add Mac to returned dict with None value to track all procedure process
    ans_dict[single_mac] = None

# put PPP port in service mode
trex_client.set_service_mode(
        ports = [ppp_port_id],
        enabled = False,
        filtered = True,
        mask = NO_TCP_UDP_MASK)

### Creation of EMU Profile obj
### This obj can be used to create configuration offline without real connection
profile2load = EMUProfile(ns = ppp_ns)

### Apply prepared profile to EMU Client
emu_client.load_profile(profile = profile2load, max_rate = 50, verbose = True)  # using EMUClient

### Core test
### Core test
### Core test
observation_time = 30
all_client_up = None
for index in range(observation_time):
    print("##################### Second %d" % index)
    # reset
    all_client_up = True
    sleep(1)

    # loop over ans_dict if value is None query it using EMUClientKey in mac2key
    for mac in ans_dict:

        # already completed and acquired
        if ans_dict[mac]:
            continue

        # single client key for EMU
        c_key = mac2key[mac]
        # boh value
        zero = True
        ver_args = [{'name': 'c_key', 'arg': c_key, 't': EMUClientKey, 'must': True},
                    {'name': 'zero', 'arg': zero, 't': bool, 'must': False}]
        EMUValidator.verify(ver_args)

        clientIP = emu_client._send_plugin_cmd_to_client(cmd='ppp_c_client_ip', c_key = c_key, zero = zero)

        if clientIP is None or clientIP == '0.0.0.0':
            all_client_up = False
        else:
            pppServerMac = emu_client._send_plugin_cmd_to_client(cmd='ppp_c_server_mac', c_key = c_key, zero = zero)
            sessionId = emu_client._send_plugin_cmd_to_client(cmd='ppp_c_client_session', c_key = c_key, zero = zero)
            TRexKeywords.logger.debug(">> %s >> (Session Id, Client IP) -> (%s, %s)" % (mac, sessionId, clientIP))
            ans_dict[mac] = (pppServerMac, sessionId, clientIP)
            all_client_up = all_client_up and True

    # if I have all IP configured after one loop -> exit
    if all_client_up:
        break

if all_client_up == False:
    msg = "XXXX After %d seconds not all %d PPP Session are established!!!" % (observation_time, nr_of_clients)
    raise Exception(msg)

####
#### Emulate PPP Clients - END
####

####
####
####
#### Use variable ans_dict to create multi stream scenario with each ppp clients that tx/rx packets
####
####
####

####
#### Disconnect from TRex
####

emu_client.remove_all_clients_and_ns()
trex_client.reset()
trex_client.release()
emu_client.disconnect()
trex_client.disconnect()

####
#### Disconnect from TRex - END
####