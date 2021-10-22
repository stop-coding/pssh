# Pssh
the tool of parallel-ssh for python

# Install
    pip install parallel-ssh

# Usage
    usage: multi_ssh.py -f [config txt] -i [ssh hosts]
       -f,--file     ip address in file, support hosts of zookeeper conf.
       -i,--ips     ip address
       -u,--user     user name of ssh, default root
       -w,--password password of ssh
       -p,--port     port of ssh
       exp: multi_ssh.py -i 127.0.0.1,192.168.1.3 -p 22 -u root -w myrootpsw