# Management VRF Design Document

## Introduction
Management VRF is a subset of Virtual Routing and Forwarding, and provides a separation between the management network traffic and the data plane network traffic. For all VRFs the main routing table is the default table for all data plane ports. With management VRF a second routing table, mgmt, is used for routing through the management ethernet ports of the switch. 

The following design for Management VRF leverages Linux Stretch kernel(4.9) Namespace concept for implementing management VRF on SONiC; refer to [design comparison](#design_comparison) for trade-offs of that approach vs. l3mdev-based design.  
 
## Requirements
| Req. No | Description                                                                                                | Priority | Comments |
|---:     |---                                                                                                         |---       |---       |
| 1       | Develop and implement a separate Management VRF that provide management plane and Data Plane Isolation
| 2       | Management VRF should be associated with a separate L3 Routing table and the management interface
| 3       | Management VRF and Default VRF should support IP services like `ping` and `traceroute` in its context
| 4       | Management VRF should provide the ability to be polled via SNMP both via Default VRF and Management VRF
| 5       | Management VRF will provide the ability to send SNMP traps both via the Management VRF and Data Network
| 7       | Dhcp Relay  - Required on Default VRF support
| 8       | Dhcp Client - Required on both default VRF and management VRF
| 9       | Enable SSH services to run in the Management VRF context and Default VRF context
| 10      | Enable TFTP services to run in the Management VRF context and Default VRF context
| 11      | Management VRF should support NTP services in its context
| 12      | Management VRF and Default VRF should support `wget`, `cURL` and HTTPS services
| 13      | Management VRF should support `apt-get` package managers in the Management VRF context
| 14      | Management VRF will provide TACACS+ support

The Scope of this design document is only limited to management VRF. 

## Design
Namespaces are a feature of the Linux kernel that partitions kernel resources such that one set of processes sees one set of resources while another set of processes sees a different set of resources. 
Without namespace (NS), the set of network interfaces and routing table entries are shared across the linux operating system. Network namespaces virtualize these shared resources by providing different and separate instances of network interfaces and routing tables that operate independently of each other, thereby providing the required isolation for management traffic & data traffic.

As of this writing, SONiC uses Debian Stretch, based on Linux 4.9 kernel, which has limited VRF support. E.g., it does not support the `CGROUPS_BPF` feature which is required for associating the application to a particular VRF. Full fledged VRF support is available only in Linux 4.15 and above. This means that the l3mdev based solution is not feasible without doing enhancements in linux kernel and in application code. Hence, the l3mdev based VRF solution has been dropped and namespace based solution has been chosen.

By default, linux comes up with the default namespace, all interfaces will be part of this default namespace. Whenever management VRF support is requried, a new namespace by name "management" is created and the management port "eth0" is moved to this namespace. Following linux commands shall be internally used for creating the same.

    C1: ip netns add management
    C2: ip link set dev eth0 netns management

The default namespace (also called default VRF) enables access to the front panel ports (FPP) and the the management namespace (also called management VRF) enables access to the management interface.
Each new VRF created will map to a corresponding Linux namespace of the same name. Once if the namespace is created, all the configuration related to the namespace happens using the "ip netns exec <vrfname>" command of linux. 
For example, IP address for the management port eth0 is assigned using the command "ip netns exec management ifconfig eth0 10.11.150.19/24" and the default route is added to the management routing table using "ip netns exec management ip route add default via 10.11.150.1".
 
     C3: ip netns exec management ifconfig eth0 <eth0_ip/mask>
     C4: ip netns exec management ip route add default via <def_gw_ip_addr>

All processes (application daemons) are running in the default namespace context.
In order to make the applications to work in both management VRF and in default VRF, these applications use the following "veth pair" solution. The veth devices are virtual Ethernet devices that act as tunnels between network namespaces to create a bridge to a physical network device in another namespace. 

                ---------------------------------------------------------
                |                      LINUX                            |
                |                                                       |
         FPP    |     ------------------           -----------------    |
         -------|-----|                |           |               |    |
         -------|-----|    Default     |           |  Management   |    |
         -------|-----|      NS        |           |     NS        |----|---- eth0
         -------|-----|                |           |               |    |
         -------|-----|                |           |               |    |
                |     ------------------           -----------------    |
                |              if2 |                    | if1           |
                |             iip2 |                    | iip1          |
                |                -------------------------              |
                |                |     veth pair         |              |
                |                |                       |              |
                |                -------------------------              |
                ---------------------------------------------------------

Two new internal interfaces "if1" and "if2" are created and they are attached to the veth pair as peers. "if1" is attached to management NS and "if2" is attached to default NS. Internal IP addresses "iip1" and "iip2" are confgiured to them for internal communication. Following linux commands are internally used for creating the same.

    C5: Create if2 & have it in veth pair with peer interface as if1
        ip link add name if2 type veth peer name if1
    
    C6: Configure "if2" as UP.
        ip link set if2 up

    C7: Attach if1 to management namespace
        ip link set dev if1 netns management

    C8: Configure an internal IP address for if1 that is part of management namespace
        ip netns exec management ifconfig if1 192.168.1.1/24

    C9: Configure an internal IP address for if2
        ifconfig if2 192.168.1.2/24



**INCOMING PACKET ROUTING**

Packets arriving via the front panel ports are routed using the default routing table as part of default NS and hence they work normally without any design change.
Packets arriving on management interface need the following NAT based design. By default, such packets are routed using the linux stack running in management NS which is unaware of the applications running in default NS. DNAT & SNAT rules are used for internally routing the packets between the management NS and default NS and viceversa. Default iptables rules shall be added in the management NS in order to route those packets to internal IP of default VRF "iip2".

Following diagram explains the internal packet flow for the packets that arrive in management interface eth0.
![Incoming Packet Flow](Management%20VRF%20Design%20Document%20NS%20Eth0%20Incoming%20Pkt.svg) 

Following diagram explains the internal packet flow for the packets that arrive in Front Panel Ports (FPP).
![Incoming Packet Flow](Management%20VRF%20Design%20Document%20NS%20FPP%20Incoming%20Pkt.svg) 

**Step1:** 
For all packets arriving on management interface, change the destination IP address to "iip2" and route it. This is achieved by creating a new iptables chain "MgmtVrfChain", linking all incoming packets to this chain lookup and then doing DNAT to change the destination IP as given in the following example.

    C10: Create the Chain "MgmtVrfChain": 
         ip netns exec management iptables -t nat -N MgmtVrfChain

    C11: Link all incoming packets to the chain lookup: 
         ip netns exec management iptables -t nat -A PREROUTING -i eth0 -j MgmtVrfChain

    C12: Create DNAT rule to change destination IP to iip2 (ex: for SSH packets with destination port 22): 
         ip netns exec management iptables -t nat -A MgmtVrfChain -p tcp --dport 22 -j DNAT --to-destination 192.168.1.2   

Similarly, add rules for each application destination port numbers (SSH, SNMP, FTP, HTTP, NTP, TFTP, NetConf) as required. Once the destination IP is changed to iip2, management namespace routing instance route these packets via the interface if1. Original destination IP will be saved & tracked using the linux conntrack table for doing the appropriate reverse NAT for reply packets.
For new application, a new rule with application destination port should be added.

**Step2:** 
After routing, use POST routing SNAT rule to change the source IP address to iip1 as given in the following example.

    C13: Add a post routing SNAT rule to change Source IP address:
         ip netns exec management iptables -t nat -A POSTROUTING -o if1 -j SNAT --to-source 192.168.1.1

Original source IP will be saved & tracked using the linux conntrack table for doing the appropriate reverse NAT for reply packets. After changing source IP packets are sent out of if1 and received in if2 in default NS. All packets will be routed using the default routing instance. These packets with destination IP iip2 are self destined packets and hence they will be handed over to the appropriate application deamons running in the default namespace.


**OUTGOING PACKET ROUTING**

Packets that are originating from application deamons running in default namespace will be routed using the default routing table. Applications that need to operate on front panel ports work normally without any design change. Applications that need to operate on management namespace need the following design using DNAT & SNAT rules.

**Applications Spawned From Shell:**

Whenever user wants the applications like "Ping", "Traceroute", "apt-get", "ssh", "scp", etc., to run on management network, "ip netns exec management <actual command>" should be used.

    C14: Execute ping in management VRF
         ip netns exec management ping 10.16.208.58

This command will be executed in the management namespace (VRF) context and hence all packets will be routed using the management routing table and management interface. 

**Applications triggered internally:**

This section explains the flow for internal applications like DNS, TACACS, SNMP trap, that are used by the application daemons like SSH (uses TACACS), Ping (uses DNS), SNMPD (sends traps). Daemons use the internal POSIX APIs of internal applications to generate the packets. If such packets need to travel via the management namespace, user should configure "--use-mgmt-vrf" as part of the server  address configuration.
These application's are using the following DNAT & SNAT iptables rules to route the packets from default VRF context to the management VRF context and sending out of management interface. Application specific design enhancement is explained below in appropriate sections.

   1) Destination IP address of packet is changed to "iip1". This results in default VRF routing instance to send all the packets to veth pair, resulting in reaching management namespace.

    C15: Create DNAT rule for tacacs server IP address
         ip netns exec management iptables -t nat -A PREROUTING -i if1 -p tcp --dport 62000 -j DNAT --to-destination <actual_tacacs_server_ip>:<dport_of_tacacs_server>

   2) Destination port number of packet is changed to an internal port number. This will be used by management namespace for finding the appropriate DNAT rule in management's iptables that is requried to identify the actual destiation IP to which the packet has to be sent.

    C16: Create SNAT rule for source IP masquerade
         ip netns exec management iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   
When Ping is executed using "ip netns exec management", the namespace context is implicit and hence no user configuration is required to specify the VRF. i.e. when user executes "ip netns exec management ping abcd.com", the ping application is spawned in the management namespace context. This application calls the DNS name resolution API in the management namespace context. DNS in turn uses the management namespace specific configuration file (/etc/netns/management/resolv.conf) if exists, or the default configuration file (/etc/resolv.conf) and sends the packet to the nameserver IP address using the management namespace routing table.
When the same ping is executed in default VRF context without "ip netns", same happens through the default namespace context.
Hence, no changes are required in DNS application.


## Implementation

Implementation of namespace based solution using Linux 4.9 kernel involves the following key design points.
1. Management VRF Creation
2. Applications/services to work on both management network and data network.

### Management VRF Creation
#### Initialization Sequence & Default Behavior
This section describes the default behavior and configuration of management VRF for static IP and dhcp scenarios. After upgrading to this management VRF supported SONiC image, the binary boots in normal mode with no management VRF created. Customers can either continue to operate in normal mode without any management VRF, or, they can run a script to configure/enable management VRF. 

##### Minigraph users - With Static IP
The SONiC binary has the minigraph.py with vrfname set to "none" for ManagementIPInterfaces. Loading the minigraph.xml and saving will create the config_db.json file which has the vrfname set to "None". Management VRF can be created by running the script create-mgmt-vrf.sh, the script will change the vrfname to the MGMT tag as "management" in the config_db.json and load it to save in ConfigDb. It will restart the "interfaces-config" service and other services. "interfaces-config" service executes the "interfaces-config.sh" script that takes care of creating the management namespace (VRF) and attaching eth0 to the management namespace. It also creates the required iptables rules explained earlier (linux commands C1 to C10). On completion of this script execution, management namespace (VRF) is created and ready for use, no reboot is required. The below figure shows the sequence of creation of management VRF.

![Flow 1](Management%20VRF%20Design%20Document%20-%20Flow%201.svg) 

##### Non-Minigraph users - With Static IP
Customers using config_db.json file for loading the configuration can run the same script create-mgmt-vrf.sh that takes care of management VRF creation as stated above. 

##### Script for DHCP
During DHCP the IP address is acquired for eth0 as a part of the dhcp protocol scripts and images can be retrieved from the dhcp server. Currently minigraph.xml and acl.json files are received using options. There will be another option to get the dhcp_mgmt_vrf.sh script which will configure the management VRF as a process of dhcp exit hooks procedure. The eth0 IP address and management VRF name will be copied to config_db.json file and saved in the ConfigDb so that application which require this information can query the ConfigDb and get the details.

![DHCP Flow](Management%20VRF%20Design%20Document%20-%20DHCP%20Flow.svg)

#### ConfigDB Schema
The upgraded config_db.json schema as follows.

```
"MGMT_INTERFACE": {
    "eth0|10.11.150.19/24": {
        "gwaddr": "10.11.150.1"
        "vrfname": "management"
     }
}
```

#### Show Commands
Following show commands need to be implemented to display the VRF configuration.

| SONiC wrapper command             | Linux command                    | Description
|---                                |---                               |---
| `show vrf`                        | `ip link show type vrf`          | Display the VRF's configured
| `show vrf <vrfname> brief`        | `ip -br link show type vrf`      | Display VRF brief info
| `show vrf <vrfname> detail`       | `ip -d link show type vrf`       | Displays VRF detailed info
| `show vrf route`                  | `ip route show`                  | Displays the default VRF routes
| `show vrf route table <table-id>` | `ip route show table <table-id>` | Displays the VRF routes for table-id
| `show vrf address <vrfname>`      | `ip address show vrf <vrfname>`  | Displays IP related info for VRF

### IP Application Design
This section explains the behavior of each application on the default VRF and management VRF. Application functionality differs based on whether the application is used to connect to the application daemons running in the device or application is running from the device.

#### Application Daemons In The Device
All application daemons run in the default namespace. All packets arriving in FPP are handled by default namespace.
All packets arriving in the management ports will be routed to the default VRF using the prerouting DNAT rule and post routing SNAT rule. Appropriate conntract entries will be created.
All reply packets from application daemons use the conntrack entries to do the reverse routing from default namespace to management namespace and then routing through the management port eth0.

#### Applications Originating From the Device
Applications originating from the device need to know the VRF in which it has to run. "ping", "traceroute","dhcclient", "apt-get", "curl" & "ssh" can be executed in management namespace using "ip netns exec management <command_to_execute>", hence these applications continue to work on both management and default VRF's without any change. Applications like TACACS & DNS are used by other applications using the POSIX APIs provided by them. Additional iptables rules need to be added (as explained in following sections) to make them work through the management VRF. 

dhclient has to be executed using "ip netns exec" in the management VRF context.

##### TACACS Implementation
TACACS is a library function that is used by applications like SSHD to authenticate the users. When users connect to the device using SSH and if the "aaa" authentication is configured to use the tacacs+, it is expected that device shall connect to the tacacs+ server via management VRF (or default VRF) and authenticate the user. TACACS implementation contains two sub-modules, viz, NSS and PAM. These module code is enhanced to support an additional parameter "--use-mgmt-vrf" while configuring the tacacs+ server IP address. When user specifies the --use-mgmt-vrf as part of "config tacacs add --use-mgmt-vrf <tacacs_server_ip>" command, this is passed as an additional parameter to the config_db's TACPLUS_SERVER tag. This additional parameter is read using the script files/image_config/hostcfgd. This script is enhanced to add/delete the following rules as and when the tacacs server IP address is added or deleted.

If the tacacs server is part of management network, following command should be executed to inform the tacacs module to use the management VRF.

    C17: Configure tacacs to use management VRF to connect to the server
         config tacacs add --use-mgmt-vrf <tacacs_server_ip>

As part of this enhancement, TACACS module maintains a pool of 10 internal port numbers 62000 to 62009 for configuring upto to 10 tacacs server in the device.
During initialization, module maintains this pool of 10 port numbers as "free" and it maintains the next available free port number for tacacs client to use.
It updates the tacacs configuration file /etc/pam.d/common-auth-sonic using the following configuration.

Ex: When user configures "config tacacs  add --use-mgmt-vrf 10.11.55.40", it fetches the next available free port (ex: 62000) and configures the destination IP for tacacs packet as "iip1" (ex: 192.168.1.1) with the next available free port (62000) as destination port as follows.

    auth    [success=done new_authtok_reqd=done default=ignore]     pam_tacplus.so server=192.168.1.1:62000 secret= login=pap timeout=5 try_first_pass

With this tacacs configuration, when user connects to the device using SSH, the tacacs application will generate an IP packet with destination IP as iip1 (192.168.1.1) and destination port as "dp1" (62000).
This packet is then routed in default namespace context, which results in sending this packet throught the veth pair to management namespace.
Such packets arriving in if1 will then be processed by management VRF (namespace). Using the PREROUTING rule specified below, DNAT will be applied to change the destination IP to the actual tacacs server IP address and the destination port to the actual tacacs server destination port number.

    C12: Create DNAT rule for tacacs server IP address
         ip netns exec management iptables -t nat -A PREROUTING -i if1 -p tcp --dport 62000 -j DNAT --to-destination <actual_tacacs_server_ip>:<dport_of_tacacs_server>
         Ex: ip netns exec management iptables -t nat -A PREROUTING -i if1 -p tcp --dport 62000 -j DNAT --to-destination 10.11.55.40:49

This packet will then be routed using the management routing table in management VRF through the management port.
When the packet egress out of eth0, POSTROUTING maseuerade rule will be applied to change the source IP address to the eth0's IP address.

    C13: Create SNAT rule for source IP masquerade
         ip netns exec management iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

With these rules, tacacs packet is then routed by the management namespace through the management interface eth0. While routing the packet, appropraite conntract entries are created by linux, which in turn will be used for doing the reverse NAT for the reply packets arriving from the tacacs server.
Following diagram explains the internal packet flow for the tacacs packets that are expected to be sent out of management interface.
![Incoming Packet Flow](Management%20VRF%20Design%20Document%20NS%20FPP%20IOutgoing%20Pkt.svg) 

#### SNMP
The net-snmp daemon runs on the default namespace. SNMP request packets coming from FPP are directly handed over using default namespace. SNMP requests from management interfaces are routed to default namespace using the DNAT & SNAT (and conntrack entries for reply packets) similar to other applications like SSH.
W.r.t. SNMP traps originated from the device, the design similar to tacacs will be implemented to route them through management namespace. 
 
#### DHCP Client 
DHCP client gets the IP address for the management ports from the DHCP server, since it is enabled on a per interface the IP address is received automatically. DHCP Client has an additional option now to get the mgmt_vrf_config.sh script from the DHCP server. This script will be run as apart of the dhcp exit hooks and will configure management VRF when the system boots or dhclient command is issued. The script will also write the vrfname and eth0 ip to config_db.json and load it to be saved to ConfigDb. Applications requiring the MGMT interface configs can be retrived from ConfigDb. The default route that is being added to the default VRF needs to be removed. If the new option in dhclient.conf is not there the system behaves in normal mode.

#### DHCP Relay 
DHCP relay is expected to work via the default VRF. DHCP Relay shall receive the DHCP requests from servers via the front-panel ports and it will send it to DHCP server through front-panel ports. No changes are reqiured.

#### DNS
DNS being a POSIX API library funntion, it is always executed in the context of the application that calls this.
DNS uses the common configuration file /etc/resolv.conf for all namespaces and it also has facility to have namespace specific configuration file. 
Whenever users wants DNS through management VRF (namespace), user should create the management namespace specific configuration file "/etc/netns/<namespace_name>]/resolv.conf" and configure the nameserver IP address in it.
When applications like Ping are triggered in the management namespace using "ip netns exec management <command>" (ex: "ip netns exec management ping google.com"), it uses the DNS POSIX API that is executed in the management namespace context which uses the configuration file "/etc/netns/management/resolv.conf" specific to the namespace. When namespace specific resolv.conf file does not exist, it uses the common configuration file /etc/resolv.conf.
Similarly when DHCP automatically fetches the domain-name-server IP address from DHCP server, it will udpate the appropriate resolv.conf file based on the context in which the DHCP client is executed.


#### Other Applications
Applications like "apt-get", "ntp", "scp", "sftp", "tftp", "wget" are expected to work via both default VRF & management VRF when users connect from external device to the respective deamons running in the device using the same DNAT & SNAT rules explained earlier.
When these applications are triggered from the device, use "ip netns exec management <command>" to run them in management VRF context. 


## Phase2

Instead of using the static scripts/steps, new CLI commands for configuration and show will be provided to create and delete VRF using config commands. Config-save command will be used to save the configuration to config_db. CLI commands, DB schema and other details will be explained in at later sections of this document.

### Configuration Commands
The following CLI can be used to Configure and show vrf's.
```
config vrf add/del <vrfName>
config vrf member add/del <vrfName> <interfaceName>
show vrf config
show vrf brief
show vrf <vrfname>
```
The following modules will be affected in phase-2 for management VRF configuration.

* swss
  * cfgmgr
    * vrfmgrd.cpp
    * vrfmgr.cpp

Configure vrf using the config cli above, this triggers the vrfmgrd to create/delete the VRF in Linux. Changes to configuration files for services are required for services to run per VRF instance.

## Linux Upgrade
When SONiC upgrades to use kernel versions >= 4.10, `ip vrf exec` command will be available and enhanced iproute2 utilities available. Applications can be spawned in the context of the VRF. E.g., when user connects to the device via management port eth0, the shell spawned for them will be bound to the management VRF context.

The namespace based design explained in this document will not be required after the upgrade.  Minimal changes will be required to support multiple services or configuration files across multiple VRF's; changes will be required to run IP services per VRF, we will revisit this and update the design document accordingly in future.

## Appendix

### <a name="design_comparison"></a>Design Approach Comparison
| Features         | Namespace                    | L3MDev
|---               |---                           |---
| Kernel Support   | Yes                          | Yes
| Scalability      | Limited                      | Better
| Protocol support | IP services replicated       | IP services enslaved to a L3 interface
| Performance      | Service replication overhead | Shared services
| Implementation   | No kernel/app change         | Kernel patch & App code change required.

The Linux kernel has brought in the l3mdev primarily to provide the VRF solution in the L3 layer. Linux kernel upgrades are also targetted towards using the L3mdev solution for VRF. Industry also uses l3mdev as the solution for VRF. But, the l3mdev support present in 4.9 kernel is limited. It is not possible to meet all the requirements without patching the kernel and without changing the application code. Hence, it is decided to use namespace solution for supporting the VRF requirements. The alternate solution that is based on "l3mdev" (given below) has been ignored due to the reasons stated below.

### L3MDEV Based Design
This solution is based on creating a separate routing table for management network. 
L3 Master Device (l3mdev) is based on L3 domains that correlate to a specific FIB table. Network interfaces are enslaved to an l3mdev device uniquely associating those interfaces with an L3 domain. Packets going through devices enslaved to an l3mdev device use the FIB table configured for the device for routing, forwarding and addressing decisions. The key here is the enslavement only affects L3 decisions. 

With l3mdev on 4.9 kernel, VRFs are created and enslaved to an L3 Interface and services like ssh can be shared across VRFs thereby avoiding overhead of running multiple instances of IP services. i.e. entire network stack is not replicated using l3mdev.

Applications like Ping, Traceroute & DHCP client already operate on a per-interface (that maps to VRF) basis. E.g., Ping accepts `-I` to specify the interface in which the ping should happen; DHCP client is enabled on a per-interface basis; hence, no enhancement is required in those application packages to run them on the required VRF. 

But, the 4.9 kernel does not support accepting UDP packets in both management VRF & data VRF. Kernel patch is required to patch `udp_l3mdev_accept` from higher kernel version. Similarly, other applications, like DNS & apt-get, do not have facility to run them on a particular interface (that maps to VRF) and always operate on default VRF. In order to make them operate via management VRF those application package code needs to be modified to specify the VRF through which they need to run. Changes are required to force the packets originated from the device to do the lookup on management routing table instead of looking up the default routing table. 


### Default Routing Table For Management Traffic
This option is based on non-standard way of visualizing the routing table. By default, all data traffic are handled via "default routing table". But, this is not mandatory. Instead, create a "blue VRF" and associate all front-panel ports to "blue VRF" and management port (eth0) is associated to default VRF. The "default VRF routing table" is "management VRF routing table" and "blue VRF routing table" as the "data routing table". This is a perception change. All the device originated applications (like DNS, apt-get) operating via management network need not be modified. They will continue to use default routing table (i.e., management VRF routing table) and send traffic via management port. Applications like Ping, Traceroute and DHCP client already operates on per-interface basis. This is not prototyped and hence there is no proof that applications can work without any change. Lastly none of the industry use this kind of perception change and hence this design option is dropped.

