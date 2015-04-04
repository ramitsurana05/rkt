# Hacking Guide

## Building rkt

### Tools Required

* Linux Kernel 3.8+ 
  * make
  * gcc compiler
  * glibc development and static pieces: 
  Fedora/RHEL/Centos: glibc-devel and glibc-static packages 
  Debian/Ubuntu: ibc6-dev package
  * cpio
  * squashfs-tools
  * realpath
  * gpg
* Go 1.3+

Once the above requirements have been met you can build rkt by running the following commands:

```
git clone https://github.com/coreos/rkt.git
cd rkt; 
./build;
```

### With Docker :

You can build rkt in a Docker container with the following command. Replace $SRC with the absolute path to your rkt source code:

```
$ sudo docker run -v $SRC:/opt/rkt -i -t golang:1.3 /bin/bash -c "apt-get update && apt-get install -y coreutils cpio squashfs-tools realpath && cd /opt/rkt && go get github.com/appc/spec/... && ./build"
```

### Running

 Launch a local application image

$ rkt run hello.aci
At this point our hello app is running on port 5000 and ready to handle HTTP requests.

### Testing with curl

Open a new terminal and run the following command:

$ curl 127.0.0.1:5000
hello
