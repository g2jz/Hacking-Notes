<!-- omit in toc -->
# Cracking WiFi

<!-- omit in toc -->
## Table of Contents

1. [Validate Handshake with Pyrit](#validate-handshake-with-pyrit)
2. [Traditional Cracking](#traditional-cracking)
   1. [John (.hccap)](#john-hccap)
   2. [Hashcat (.hccapx)](#hashcat-hccapx)
   3. [Aircrack (.cap)](#aircrack-cap)
   4. [Pyrit (.cap)](#pyrit-cap)
   5. [Cowpatty (.cap)](#cowpatty-cap)
3. [Precomputed Password Cracking](#precomputed-password-cracking)
   1. [Fundamentals](#fundamentals)
   2. [Aircrack](#aircrack)
   3. [Genpmk](#genpmk)
      1. [Pyrit](#pyrit)
      2. [Cowpatty](#cowpatty)
      3. [Aircrack (Conversion)](#aircrack-conversion)
   4. [Pyrit BBDD Attack](#pyrit-bbdd-attack)
4. [Rainbow tables](#rainbow-tables)
   1. [Fundamentals](#fundamentals-1)
   2. [Online Resources](#online-resources)

<br>

## Validate Handshake with Pyrit

```bash
pyrit -r Handshake.cap analyze
```

Two posible answers:

- No valid EAOPL-Handshake.
- Valid Handshakes (ESSID and Clients).

<br>

## Traditional Cracking

### John (.hccap)

The first thing to do, is to convert the *.cap* file to a *.hccap* file. We can use *aircrack-ng*  and *-J* for this porpouse:

 ```bash
 aircrack-ng -J newName Handshake.cap
 ```

This will create the *.hccap* file.

Once we have got the *.hccap* file, we can use a tool like *hccap2john* to convert this file to a hash:

```bash
hccap2john Handshake.hccap > HandshakeHash
```

To crack the hash with *rockyou.txt* wordlist:

```bash
john --wordlist=rockyou.txt HandshakeHash --format=wpapsk
```

View cracked hash:

```bash
john --show --format=wpapsk HandshakeHash
```

### Hashcat (.hccapx)

The main benefit of using Hashcat is that the cracking process can be made with GPU. This will make the process way faster.

First of all, we need to convert our *.cap* file containing the Handshake to a *.hccapx* file. We can use *aircrack-ng* and *-j*  for this:

```bash
aircrack-ng -j newName Handshake.cap
```

Once we have got the *.hccapx* file, we can proceed to the cracking stage:

```bash
hashcat -m 2500 -d 2 -w 3 Handshake.hccapx rockyou.txt 
```

To undestand what we have done, we are going to explain each tag in the command. First *-m* indicates the mode of the hash to crack. In this case, we have a *.hccapx* file that contains the EAPOL (Handshake packages) of the WPA protocol, so we are going to use the 2500 mode (All modes can be displayed with *hashcat -h*). Then with *-d* we can control what device is going to crack the password (1 -> CPU or 2 -> GPU). With the *-w* parameter we can control the different workload profiles (1 -> Low, 2 -> Default, 3 -> High, 4 -> Nightmare).

Finally, to view the cracked password:

```bash
hashcat --show -m 2500 Handshake.hccapx
```

### Aircrack (.cap)

We can use *aircrack-ng* if we want to use the raw *.cap* file. This will be considerably slower than the *Jhon* method.

```bash
aircrack-ng -w rockyou.txt Handshake.cap
```

### Pyrit (.cap)

We can use *Pyrit* too, for this porpouse. Considerably slower than *Jhon* too.

```bash
pyrit -e ESSID -i rockyou.txt -r Handshake.cap attack_passthrough
```

### Cowpatty (.cap)

Finally, with raw *.cap* files, we can use *Cowpatty* too. Slower than *John*, *Aircrack* and *Pyrit*.

```bash
cowpatty -f rockyou.txt -r Handshake.cap -s ESSID
```

<br>

## Precomputed Password Cracking

### Fundamentals

With traditional cracking, the steps made to compare our raw *.cap* file to each word in the plain text wordlist are:

- Filtration of the capture to extract the Handshake hash.
- Reading of the wordlist (CCMP of each plain password is computed).
- Comparison of the computed hashes with the hanshake hash.
- True/False (True means the password has matched, hence it has been succesfully cracked).

With a Pairwise Master Keys (PMKs) wordlist the steps made for each password are:

- Reading of the PMK password from the wordlist.
- True/False.

This obviously accelerates the process of cracking and we can achieve very good cracking speeds even with low computational resources.

### Aircrack

In this case, we are going to convert a traditional plain text wordlist to a PMKs wordlist. This will make way faster the cracking process, since there will be less steps in the comparison step.

First, we will create our PMKs wordlist (Basically is a database) and populate the passwd column with our wordlist:

```bash
airolib-ng PMKsWordlist --import passwd rockyou.txt
```

Once we have the PMKs wordlist, we will create a *essid.lst* file containing the ESSID of the network:

```bash
echo "ESSID" > essid.lst
```

Then, we will import the *essid.lst* file to the PMKs wordlist with the following command:

```bash
airolib-ng PMKsWordlist --import essid essid.lst
```

We can use the following command to see if everything is correctly defined:

```bash
airolib-ng PMKsWordlist --stats
```

*Airolib-ng* has a utility to clean the passwords and the ESSIDs in our PMKs Wordlist. This utility removes the blank and non readable elements. We can use it with the following command:

```bash
airolib-ng PMKsWordlist --clean all
```

Lastly, we can use the following command to convert all the plain passwords to PMKs:

```bash
airolib-ng PMKsWordlist --batch
```

We can verify if the PMKs wordlist has been succesfully created using the *--verify* tag in *airolib-ng*. This command will test 10.000 randomly chosen PMKs:

```bash
airolib-ng PMKsWordlist --verify
```

Once we have the PMKs wordlist, we can crack our *.cap* file with *aircrack-ng* using the following syntax:

```bash
aircrack-ng -r PMKsWordlist Handshake.cap
```

This method is very fast compared to traditional cracking, but with other tools like *Cowpatty* or *Pyrit* speed can be improved.

### Genpmk

We have seen how to create the PMKs wordlist with the *aircrack-ng* suite, now we are going to see a tool called *Genpmk*. This tool allows us to create a PMKs wordlist that can be used with various tools.

To create the PMKs wordlist we will use the following command:

```bash
genpmk -f rockyou.txt -d dic.genpmk -s ESSID
```

#### Pyrit

Now, we will use the previously created wordlist with the *Pyrit* tool. This tool will give us one of the fastest cracking rates of all methods.

To crack the *.cap* file with our PMKs wordlist we will do the following:

```bash
pyrit -i dic.genpmk -e ESSID -r Handshake.cap attack_cowpatty
```

#### Cowpatty

Altenatively, we can crack the password using the wordlist generated with *Genpmk* and the *Cowpatty* tool. This tools will not have as good results as *Pyrit*, but when compared with other methods it can be pretty fast.

```bash
cowpatty -d dic.genpmk -r Handshake.cap -s ESSID
```

#### Aircrack (Conversion)

We have explained how to create a PMKs wordlist with *airolib* and how to crack it with *aircrack-ng*. Alternatively *airolib-ng* offers the feature to generate its own format PMKs wordlist on the basis of *Genpmk* generated wordlist. To do this, we will use the following command:

```bash
airolib-ng PMKsWordlist --import cowpatty dic.genpmk
```

### Pyrit BBDD Attack

This is the method that will give us the fastest cracking rate of all of the ones above. First of all, we are going to estar importing our plain text wordlist in the *Pyrit* tool:

```bash
pyrit -i rockyou.txt import_passwords
```

Next, we will define the ESSID that we are going to use:

```bash
pyrit -e ESSID create_essid
```

Then, we will generate the PMKs wordlist using the following command:

```bash
pyrit batch
```

Lastly, we are going to perform the cracking stage:

```bash
pyrit -r Handshake.cap attack_db
```

<br>

## Rainbow tables

### Fundamentals

This method consists in a series of huge tables (Hundreds of GB or some TB) that store plain text passwords with their corresponding hashes. This hashes are not stored fully in the tables, since they use a method called reduction, that transforms them into a light version, that then, can be restored applying the reverse of the reduction function. This allows to store a huge amount of passwords, since the way this data is accesed is based in "bookmarks". The finding of the hash is done by a process that increasingly narrows down the possible hashes and eventually finds the correct one. Ones we have the correct hash we only have to see its associated plain text password-

### Online Resources

Since this tables need a very big amount of storage, we can use online resources that host Rainbow Tables, to compare our hash with those tables. This will make a comparation with a huge wordlist of precompute passwords, thus we will have a huge speed.

This resources are:

- [CrackStation](https://crackstation.net/)
- [Hashes.com](https://hashes.com/en/decrypt/hash)
- [HashKiller](https://hashkiller.io/)
