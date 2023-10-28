<br>
<h2 align=center id=group>Group member<h1>
<p align=center>
<a href="https://cri.epita.fr/users/antoine.adam/"><img src="https://img.shields.io/badge/-Antoine%20ADAM-lightblue"></a>
<a href="https://cri.epita.fr/users/leo.vongchanh/"><img src="https://img.shields.io/badge/-L%C3%A9o%20VONGCHANH-lightblue"></a>
<a href="https://cri.epita.fr/users/axel.was/"><img src="https://img.shields.io/badge/-Axel%20WAS-lightblue"></a>
</p>

<h1 align="center">
HTTPS proxy project supporting SSL and TLS (implementation of <a href="https://mitmproxy.org/">mitmproxy</a>).
</h1>
<p align="center">This is a student project and the the HTTP support wasn't asked to be implemented.</p>

## Table of contents

- [Dependencies](#dependencies)
- [Configurations](#configurations)
  - [CA setup](#ca-setup)
  - [Firefox setup](#firefox-setup)
  - [Cmake executable generation](#cmake-executable-generation)
- [Usage](#usage)
  - [Basic proxy](#basic-proxy)
  - [Full proxy](#full-proxy)
    - [Regex](#regex)
    - [Interactive](#interactive)
- [Features](#features)
  - [Dynamic certificate generation](#dynamic-certificate-generation)
  - [Front-end socket for the data inspector](#front-end-socket-for-the-data-inspector)
  - [Configurable Malware analysis](#configurable-malware-analysis)
  - [Man page](#Man-page)
  - [Python library](#python-library)
- [Websites test](#websites-test)
- [Known Issues and Limitations](#known-issues-and-limitations)
- [Prototypes](#prototypes)

---

## Dependencies

- GNU/Linux system
- Firefox (any recent version is fine)
- cmake 3.26.4 (version under it might work too)
- python 3.11.x
- Openssl 3.1.1

---

## Configurations

---

### CA setup

Make sure every dependencies is installed before this step.

Generate a certificate authority(CA) with Openssl(go to the next [step](#firefox-setup) if you have one):

```shell
openssl genrsa -des3 -out ca.key 4096
```

- This command generates a 4096-bit RSA private key (ca.key) encrypted with Triple DES (3DES).
    - The `-des3` flag specifies the encryption algorithm.
    - The `-out ca.key` flag specifies the output file where the private key will be stored.
    - The `4096` parameter specifies the key length in bits.

<p align="center"><b>Triple DES (3DES) for encryption is considered outdated. This is intentional. AES is recommended instead.</b></p>

```shell
openssl req -new -x509 -days 365 -key ca.key -out ca.crt
```

**Don't put a password on your .crt. Or it won't work.**

- This command generates a self-signed X.509 certificate (ca.crt) using the previously generated private key.
    - The `-new` flag indicates that a new certificate request is being made.
    - The `-x509` flag specifies that a self-signed certificate is desired.
    - The `-days 365` flag sets the validity period of the certificate to 365 days.
    - The `-key ca.key` flag specifies the private key to be used for signing the certificate.
    - The `-out ca.crt` flag specifies the output file where the self-signed certificate will be stored.

<p align="center"><b>The validity period of 365 days for a CA certificate is relatively short, and longer validity periods are often used in practice.</b></p>

Now you have 2 new files: `ca.key` and `ca.crt`. If you are not going to test this project and use it for practice, you can put the "ca.key" path in an environnement variable definitely, so you don't have to do it each time you start the proxy.

To do so, you need to add the following line in your `.bashrc` or `.zshrc`:

```shell
export PROXY_CA_KEY=path/to/key
```

*Don't add the extension of the key file. Just the name of it.*

Don't forget to "reload" the file to apply the change to the current terminal:

```shell
source .bashrc
```

---

### Firefox setup

Add the certificate in Firefox now : *settings* > *privacy & security* > *certificates* > *view certificates* > *import...* > **Import `ca.crt`**

Setup the proxy : *settings* > *general* > *network settings* > *settings*

Check manual proxy and fill the "HTTPS" line with `localhost` and "port" with `8443`.

---

### Cmake executable generation

This is the final step where we get the executable needed to start the proxy.

```shell
cmake .
```
This command generate a Makefile for the compilation of the executable.

You can already generate the executables needed with:

```shell
make basic_proxy
make full_proxy
```

Those commands will generate `full_proxy.bin` and `basic_proxy.bin`.

If there is warning in the compilation, it's fine.

You can always use `make clean` to clean the directory if needed.

---

## Usage

```txt
Usage: [ENV VAR PROXY_INTERACTIVE_PORT] [ENV VAR PROXY_REGEX] <ENV VAR PROXY_CA_KEY> ./full_proxy.bin [options]

Options:
 -h / --help Show this message and exit

ENV VAR:
 PROXY_CA_KEY
 PROXY_REGEX
 PROXY_INTERACTIVE_PORT
```
You generated 2 executables with the commands used [above](#cmake-executable-generation), so this section will cover both ways to use them.

**It's important to note that not all the websites works, so we made a small list of what works and doesn't [here](#test).

---

### Basic proxy

This is the backup version of the full proxy version. **ONLY** use it when the full proxy isn't working.

This proxy doesn't implement the regex and interactive options.

If you didn't set the PROXY_CA_KEY environnement variable globaly, start the executable like that:

```shell
PROXY_CA_KEY=/path/to/ca_key ./basic_proxy.bin
```

*Don't add the extension of the key file. Just the name of it.*

---

### Full proxy

This is the executable we recommend using. It implement the regex for the malware analysis and the interactive mode for the packet analyzer in python, more details will be provided under this section.

This command will be a simple proxy without regex and interactive mode:

```shell
PROXY_CA_KEY=/path/to/ca_key ./full_proxy.bin
```

*Don't add the extension of the key file. Just the name of it.*

If you want to use both implementation:

```shell
PROXY_CA_KEY=/path/to/ca_key PROXY_INTERACTIVE_PORT=8945 PROXY_REGEX="en599" ./full_proxy.bin
```

**You can change the port for the interactive mode and choose the regex you want to use. For the interactive mode, you will find how to use it [here](#interactive).**

### Regex

This option is an implementation for malware analysis with regex. It will try to find a match for the regular expresion in every network packet going through our proxy.

If the regex is matching, the transfert of the packet will stop.

```shell
PROXY_CA_KEY=/path/to/ca_key PROXY_REGEX="en599" ./full_proxy.bin
```

**Change the regex with the one you want to use.**

### Interactive

This option is used to analyse the network packet traffic using a python program.

To use it, you need to start the executable then start the python file:

```shell
PROXY_CA_KEY=/path/to/ca_key PROXY_INTERACTIVE_PORT=8945 ./full_proxy.bin
python3 proxy.py
```

**Use 2 differents terminals for it.**

---

## Features

### Dynamic certificate generation

SSL certificate spoofing is a critical feature of our proxy program. It allows the proxy to intercept and read secure HTTPS communications by presenting a fake certificate to the client. This fake certificate is a copy of the original server's certificate but signed by a Certification Authority (CA) controlled by the proxy.

Please note that it's not necessary to add the `.key` extension at the end of the path. The program automatically appends this extension to also get the corresponding `.crt` certificate.

We have implemented a test executable for this feature alone. If you want to try it, you can use the make file for that. **Make sure you already made the cmake command to generate the Makefile.**

**Don't forget to set the CA key and cert in the "CA_CERT_FILE" and "CA_KEY_FILE" of the `generate_custom_certificat.c` file before using it.**

Generate the test executable:

```shell
make usurpation
```
It will generate the file `usurpation.bin`. After executing it, the memory leak is a normal behaviour here but most importantly if you see `everything is fine` when scrolling up, that means the fake certificate is working.

<details><summary>More details</summary>

Furthermore, the file `generate_custom_certificat.c` is a complete prototype for certificate copying. It's fully functional and served as the basis for setting up the SNI callback in the proxy program. If both proxies fail to work, this file can serve as a fallback solution. It allows fetching the target server's certificate, generating a new RSA key pair, creating a new certificate with the new public key, copying all the server's certificate information into the new certificate, signing the new certificate with the CA's private key, displaying the details of both certificates, and saving both certificates as well as the new certificate's private key into files.

</details>

---

### Front end socket for the data inspector

The Interactive Socket and its associated Python Library are two key features of our Proxy. Their purpose is to allow for detailed interpretation of decrypted HTTPS requests and responses, while facilitating the filtering, transformation, and resending of HTTP packets. Here is a detailed guide on their use:

Interactivity is an optional feature that can be enabled by setting the `PROXY_INTERACTIVE_PORT` environment variable. This points to an unencrypted port used to interpret decrypted HTTPS requests.

The Python Library provides a proxy module in Python 3.11 for intercepting (using the interactive socket of `full_proxy.c`), parsing headers, filtering HTTP packets, transforming the body/header, then reforming and sending back the packet.

Inside the `proxy.py` file, you will find a detailed usage example of the proxy module.

It is important to note that the Python Library provides tools for working with the Interactive Socket and should not be considered a complete solution in itself. You can use it as a basis for developing more advanced or specific functionalities according to your needs.

The Interactive Socket and Python Library are powerful features for manipulating and analyzing data passing through the Proxy. While their use might require some networking and HTTP programming experience, their flexibility and customization potential make them a valuable tool for a variety of use cases.

---

### Configurable malware analysis

The regex detection feature is optional and can be activated by defining a PROXY_REGEX environment variable with the desired regular expression's value. For example: PROXY_REGEX="the regex".

In our proxy system, we have integrated a malware detection feature based on regular expressions, also known as regex. This feature is designed to intercept and analyze the traffic between the client and the server, allowing real-time monitoring of the content of exchanges.

Regular expressions are used to analyze the requests and responses passing through the proxy. The buffer, used to pass data from one socket to another, is analyzed by the regex. If the buffer content matches the defined regular expression, the data transfer is halted. This allows the interception and potential stoppage of malicious data transfer.

--- 

### Man page

There is a 2 man pages: `basic_proxy.1` and `full_proxy.1`.

Use them with the `man` command:

```shell
man ./full_proxy.1
```

---

### Python library

<details><summary>The Interactive Socket works on both requests and responses. For this, a header is added to indicate whether the communication is a request or a response, as well as the port and IP (that of the connect). Here is the general operation scheme:</summary>

```
Request: browser -- SSL_SOCKET -> proxy -- SOCKET -> interactive_tool -- SOCKET -> proxy -- SSL_SOCKET -> server
Response: server -- SSL_SOCKET -> proxy -- SOCKET -> interactive_tool -- SOCKET -> proxy -- SSL_SOCKET -> browser
```

</details>

<details><summary>The format of the added header is as follows:</summary>

```
Version, type[REQUEST|RESPONSE], ip, port, [the request or the response]
V1,RESPONSE,%s,%d,...
```

</details>

**This header is only added for the proxy -> interactive_tool direction, it is not added for the interactive_tool -> proxy direction.**

---

## Websites test

Here are some sites where you can test the proxy:

- Works:
    - https://www.exploit-db.com/google-hacking-database
    - https://www.offsec.com/
- Partially works:
    - https://www.y2mate.com/
- Works rarely or not at all:
    - https://www.kali.org/tools/
    - https://developer.mozilla.org/fr/docs/Web/HTTP/Methods/TRACE

**It is recommended to test on several different sites because the results can be random.**

---

## Known Issues and Limitations

1. **Proxy Instability**: The proxy can sometimes terminate unexpectedly. This behavior seems to be random and has not been resolved to date. It is likely that this instability is related to disconnection issues with the browser. This issue is still under investigation, and we apologize for any inconvenience it may cause.

2. **Blocking Read Issue**: When reading data from a socket, if a read attempt is made when there are no more data to read, the process becomes blocked. Several strategies have been tried to resolve this problem:

   - **HTTP Headers Parsing**: This approach involves detecting the `content-length` value to know the number of bytes in the body of the message and stopping the read at the end of the header if `content-length` is not present. However, this doesn't always work as many modern HTTP requests/responses are chunked for data optimization. 

   - **Use of `select` Function**: This method allows putting a timeout on the read operation, which solves the problem of blocking read. However, it introduces latency and can stop the transfer if the server takes too long to respond.

   - **Buffer Fill Check**: If the buffer is not completely filled, it means we are at the end of the packet. However, this solution is not perfect as it may block the read if the last byte of the packet fills the last byte of the buffer.

   The ideal solution would likely be a combination of parsing (with consideration of `chunked encoding`) and a safety timeout.

3. **Pattern Detection Issues with Yara or Regex**: We have not implemented a sliding buffer, so if a pattern is split into two by the buffer, it will not be detected. The optimal solution would be to create a sliding buffer of dynamic size, allocated once after the size of the largest pattern has been calculated.

4. **Data Compression Limitations**: Regex doesn't work very well most of the time, as servers often compress data before sending, which can make pattern detection difficult.

5. **Custom Certificate Generation**: The `generate_custom_certificat.c` file is a complete prototype of certificate copying. It is functional but primarily serves as a backup if the two proxies do not work. Ensure to correctly set the CA in the defines at the top of the `generate_custom_certificat.c` file.

6. **Website Compatibility**: Not all websites work perfectly with our proxies. Some sites work well, while others may have issues or not work at all. It's recommended to test on multiple sites for a better evaluation.

---

## Prototypes

- prototypes/parsing_header.c : HTTP header parser, we removed the error from the other version with the sliding buffer
- prototypes/proxy_https_v1.c : it's the first version of the proxy without any bonus, it is very functional due to the blocking read, it was before seeing you for the Thursday class
- prototypes/socket_to_socket.c : it's the solution of the select with the timeout for the blocking read
- prototypes/yara.c : the yara part that should have been implemented in full_proxy.c 

[BACK TO THE TOP](#group)
