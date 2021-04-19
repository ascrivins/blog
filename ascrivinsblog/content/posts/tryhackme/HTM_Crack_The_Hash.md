---
title: "[TryHackMe] Crack the hash - Walkthrough"
date: 2021-04-16T08:14:23-04:00
author: ascrivins
description: "A complete, step-by-step walkthrough of the crack the hash room on TryHackMe"
ShowToc: true
ShowBreadCrumbs: true
ShowReadingTime: true
ShowPostNavLinks: true
ShowShareIcons: true


categories: ["TryHackMe"]
tags: ["Walkthrough", "Hash Cracking", "hashcat"]
cover:
   image: "/post_images/crackthehash/banner.png"

---
# Intro

Link to room: https://tryhackme.com/room/crackthehash

> **Note:** Some of the hashes will take a long time to crack. 

------------------------------------------------

# Level 1
## Hash 1: 48bb6e862e54f2a795ffc4e541caed4d
This hash can be cracked by using a online tool to search through a database of cracked hashes. 

 1. Head to: https://hashes.com/en/decrypt/hash 
 2. Copy in the hash and press Submit.  
 3. This gives us the result and algorithm:

`    48bb6e862e54f2a795ffc4e541caed4d:[Redacted]:MD5`

------------------------------------------------

## Hash 2: CBFDAC6008F9CAB4083784CBD...
This hash can be cracked by using a online tool to search through a database of cracked hashes. 

 1. Head to: https://hashes.com/en/decrypt/hash 
 2. Copy in the hash and press Submit.  
 3. This gives us the result and algorithm:

 `   cbfdac6008f9cab4083784cbd1874f76618d2a97:[Redacted]:SHA1`

------------------------------------------------

## Hash 3: 1C8BFE8F801D79745C4631D09F...
This hash can be cracked by using a online tool to search through a database of cracked hashes. 

 1. Head to: https://hashes.com/en/decrypt/hash 
 2. Copy in the hash and press Submit.  
 3. This gives us the result and algorithm:

 `   1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032:[Redacted]:SHA256PLAIN`

------------------------------------------------

## Hash 4: \$2y\$12\$Dwt1BZj6pcyc3Dy1FWZ5ieeUz...
This is where it gets a little more tricky. Using the online tool doesn't yield any results so we need to crack the hash. 

Firstly, we need to identify the algorithm. We can do this with the Hash Identifier tool on hashes.com.

This gives the result: 

    Possible algorithms: bcrypt $2*$, Blowfish (Unix)

We can look up the hashcat mode for this algorithm here: https://hashcat.net/wiki/doku.php?id=example_hashes 

Hashcat Mode #: 3200

Then running this through Hashcat with the command:

    hashcat -a 3 -m 3200 blowfish.txt ?l?l?l?l

where:
 - -a 3 is attack mode=3 which is brute force
 - -m 3200 is the mode for Bycrpt Blowfish
 - blowfish.txt is the file containing just the hash
 - ?l?l?l?l specifies it's a 4 letter word with char a-z

Gives result:

    $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:[Redacted]
                                                     
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: bcrypt $2*$, Blowfish (Unix)
    Hash.Target......: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX...8wsRom
    Time.Started.....: Sat Apr 17 06:46:13 2021 (1 min, 35 secs)
    Time.Estimated...: Sat Apr 17 06:47:48 2021 (0 secs)
    Guess.Mask.......: bl?l?l [4]
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:        6 H/s (9.64ms) @ Accel:2 Loops:64 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 604/676 (89.35%)
    Rejected.........: 0/604 (0.00%)
    Restore.Point....: 600/676 (88.76%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4032-4096
    Candidates.#1....: bleh -> bllz


------------------------------------------------


## Hash 5: 279412f945939ba78ce0758d3fd83daa
Here we can return to using a online tool to search through a database of cracked hashes. 

 1. Head to: https://hashes.com/en/decrypt/hash 
 2. Copy in the hash and press Submit.  
 3. This gives us the result and algorithm:

  `  279412f945939ba78ce0758d3fd83daa:[Redacted]:900`

------------------------------------------------


# Level 2
## Hash 6: F09EDCB1FCEFC6DFB23DC3505A882...
This hash can be cracked by using a online tool to search through a database of cracked hashes. 

 1. Head to: https://hashes.com/en/decrypt/hash 
 2. Copy in the hash and press Submit.  
 3. This gives us the result and algorithm:

  `  f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:[Redacted]:SHA256PLAIN`

------------------------------------------------


## Hash 7: 1DFECA0C002AE40B8619ECF94...
This hash can be cracked by using a online tool to search through a database of cracked hashes. 

 1. Head to: https://hashes.com/en/decrypt/hash 
 2. Copy in the hash and press Submit.  
 3. This gives us the result and algorithm:

  `  1dfeca0c002ae40b8619ecf94819cc1b:[Redacted]:NTLM`

------------------------------------------------


## Hash 8: \$6\$aReallyHardSalt$6WKUTqzq.U...
Salt: aReallyHardSalt & Rounds: 5

Firstly, we need to identify the algorithm. We can do this with the Hash Identifier tool on hashes.com.

This gives the result: 

    Possible algorithms: sha512crypt $6$, SHA512 (Unix)

We can look up the hashcat mode for this algorithm here: https://hashcat.net/wiki/doku.php?id=example_hashes 

Hashcat Mode #: 1800 - sha512crypt

Then running this through Hashcat with the command:


    hashcat -m 1800 hash.hash wordlists/rockyou.txt 

where:
 - -m 1800 is the mode for sha512crypt
 - hash.hash is the file containing just the hash
 - wordlists/rockyou.txt is the dictionary to check against. 

Gives result:

    $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.:[Redacted]
                                                     
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: sha512crypt $6$, SHA512 (Unix)
    Hash.Target......: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPM...ZAs02.
    Time.Started.....: Fri Apr 16 10:25:11 2021 (1 hour, 17 mins)
    Time.Estimated...: Fri Apr 16 11:42:52 2021 (0 secs)
    Guess.Base.......: File (wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:      685 H/s (9.52ms) @ Accel:32 Loops:512 Thr:1 Vec:4
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 2831936/14344385 (19.74%)
    Rejected.........: 0/2831936 (0.00%)
    Restore.Point....: 2831872/14344385 (19.74%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4608-5000
    Candidates.#1....: wakaguma -> wak3Board

------------------------------------------------

## Hash 9: e5d8870e5bdd26602cab8dbe07a942...
Salt: tryhackme

Firstly, we need to identify the algorithm. We can do this with the Hash Identifier tool:

This gives the result: 

     HASH: e5d8870e5bdd26602cab8dbe07a942c8669e56d6
    
    Possible Hashs:
    [+] SHA-1
    [+] MySQL5 - SHA-1(SHA-1($pass))

The hint tells us the algorithm is HMAC-SHA1 so the identifier is not being helpful here.
Hashcat Mode #: 160 - HMAC-SHA1
> **Note:** The mode is not 110 as the other walkthroughs say. ;)

Then running this through Hashcat with the command:

    hashcat -m 160 sha1.txt wordlists/rockyou.txt

where:
 - -m 160 is the mode for HMAC-SHA1
 - hash.hash is the file containing: hash:salt
 - wordlists/rockyou.txt is the dictionary to check against. 

Gives Result:

    e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:[Redacted]
                                                     
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: HMAC-SHA1 (key = $salt)
    Hash.Target......: e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme
    Time.Started.....: Fri Apr 16 10:19:57 2021 (7 secs)
    Time.Estimated...: Fri Apr 16 10:20:04 2021 (0 secs)
    Guess.Base.......: File (wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  1570.3 kH/s (0.82ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 12314624/14344385 (85.85%)
    Rejected.........: 0/12314624 (0.00%)
    Restore.Point....: 12312576/14344385 (85.84%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidates.#1....: 48162450 -> 481101133