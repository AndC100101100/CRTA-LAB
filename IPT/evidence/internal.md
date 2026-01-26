By this point of the engagement we know there is a possible point of access into an internal network. Our external engagement left us with a set of credentials and a internal facing interface.

A set of credentials in plain text.
```
http://192.168.98.30/admin/index.php?user=john@child.warfare.corp&pass=User1@#$%6|||1737028407427000|1737029666390000|tuXr2pTr03P2|1|7
```
Some important information we get from our linpeas scan not involving vulnerabilities.
```
                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
ens32: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.80.10  netmask 255.255.255.0  broadcast 192.168.80.255
        ether 00:50:56:96:17:f9  txqueuelen 1000  (Ethernet)
        RX packets 152365  bytes 176914936 (176.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 125048  bytes 19022214 (19.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens34: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.98.15  netmask 255.255.255.0  broadcast 192.168.98.255
        ether 00:0c:29:28:1b:7e  txqueuelen 1000  (Ethernet)
        RX packets 8924  bytes 2918390 (2.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10163  bytes 2226934 (2.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        device interrupt 16  base 0x1000  

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 13972  bytes 4745588 (4.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13972  bytes 4745588 (4.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

# Configuring Ligolo

On our attacking host we will be downloading ligolo, both the agent and the proxy
```
#Proxy  
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz


#Agent  
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
```