import getopt
import os
import re
import sys
import termios
import tty
import kazoo
from pssh.clients import ParallelSSHClient


class ReadCmd(object):
    KEY_TAB = 'tab'
    KEY_EXIT = 'exit'
    KEY_ENTER = 'enter'

    def __init__(self, showtxt='[]# '):
        self.break_cmds  ={'0x9':self.KEY_TAB, '0x3':self.KEY_EXIT, '0xd':self.KEY_ENTER,}
        self.indata = ''
        self.showtxt = showtxt
        self.history_cmd=[]
        self.action={'0x8':self.do_delete, '0x1b0x5b0x41':self.do_previous_cmd,'0x1b0x5b0x42':self.do_next_cmd}
    
    def strToHexStr(str):
        ret=''
        for ch in str:
            ret+= '%#x'%ord(ch)
        return ret
    
    def clearShowNew(self, old, new):
        if len(old):
            print(chr(27) + "[%dD" %(len(old)), end='', flush=True)
            print(chr(27) + "[K", end='', flush=True)
        print(new, end='', flush=True)

    def do_end(self, key, data):
        if key == self.KEY_TAB:
            return
        if self.history_cmd.count(data) > 0:
            return
        if len(data) == 0:
            return
        self.history_cmd.append(data)
        if len(self.history_cmd) > 100:
            self.history_cmd.pop(0)

    def do_delete(self):
        if len(self.indata) == 0:
            return
        print(chr(27) + "[1D", end='', flush=True)
        print(chr(27) + "[K", end='', flush=True)
        self.indata = self.indata[:-1]

    def do_previous_cmd(self):
        if len(self.history_cmd) == 0:
            return
        if len(self.indata):
            self.history_cmd.insert(0, self.indata)
        old = self.indata
        self.indata = self.history_cmd.pop()
        self.history_cmd.insert(0, self.indata)
        self.clearShowNew(old, self.indata)

    def do_next_cmd(self):
        if len(self.history_cmd) == 0:
            return
        if len(self.indata):
            self.history_cmd.append(self.indata)
        old = self.indata
        self.indata = self.history_cmd.pop(0)
        self.history_cmd.append(self.indata)
        self.clearShowNew(old, self.indata)


    def strToHexStr(self, str):
        ret=''
        for ch in str:
            ret+= '%#x'%ord(ch)
        return ret
    
    def get(self, cmd='', show=''):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        key = self.KEY_ENTER
        if len(show):
            self.showtxt = show
        self.indata = cmd
        try:
            combination=''
            while True:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
                charhex = self.strToHexStr(ch)
                if charhex == "0x1b":
                    combination += ch
                    continue
                if len(combination) > 0:
                    combination+=ch
                    if len(combination) == 3:
                        charhex = self.strToHexStr(combination)
                        combination = ''
                        ch = ''
                    else:
                        continue
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                if charhex in self.break_cmds:
                    key = self.break_cmds[charhex]
                    break
                elif charhex in self.action:
                    self.action[charhex]()
                    continue
                elif len(ch) and ch.isprintable():
                    print(ch, end='', flush=True)
                    self.indata+=ch
                else:
                    pass  
        except Exception as e:
            print("get: {0}".format(e))
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            self.do_end(key, self.indata)
            print('')
        return key, self.indata

class multi_ssh(object):
    def __init__(self, cmdHead='pssh#: ', host=[], user='root', password='123123', port=22):
        self.cmdHead = cmdHead
        self.myhosts = host
        self.user = user
        self.password = password
        self.port = port
    def print_line(self, *args, **kwargs):
        print(self.cmdHead, args, kwargs)

    def run(self):
        try:
            if len(self.myhosts) == 0:
                print('host is empty')
                return None
            client = ParallelSSHClient(hosts= self.myhosts, user=self.user, password=self.password, port=self.port)
            io = ReadCmd(self.cmdHead)
            pre_cmd =''
            while True:
                print(self.cmdHead, end='', flush=True)
                type, data  = io.get(pre_cmd, show=self.cmdHead)
                if type == ReadCmd.KEY_EXIT or data == ReadCmd.KEY_EXIT:
                    break
                if type != ReadCmd.KEY_ENTER:
                    pre_cmd = data
                    continue
                print(data)
                out = client.run_command(data, read_timeout=3)
                for host_out in out:
                    if host_out.stderr is not None:
                        for line in host_out.stderr:
                            print(line)
                    if host_out.stdout is not None:
                        for line in host_out.stdout:
                            print(line)
        except Exception as e:
            self.print_line("run: {0}".format(e))

def read_hosts_on_file(path):
    if not os.path.isfile(path):
        return []
    txt=''
    with open(path, 'r') as f:
        txt = f.read()
    hosts = []
    for host in txt.split('\n'):
        if re.match(r'server\.(.*)=(.*:)?', host) is not None:
            (_, addr_ports) = host.split('=', 1)
            (host, _) = addr_ports.split(';')
            (ip, _, _, _) = host.split(':')
            if ip.find('10.', 0, 3) >= 0:
                ip = ip.replace('10.', '172.', 1)
            hosts.append(ip)
        else:
            hosts.append(host)
    return hosts

def help(argv, param):
    print("usage: %s -f [config txt] -h [ssh hosts]" %(argv[0]))
    print("       -f,--file     ip address in file" )
    print("       -i,--ips     ip address")
    print("       -u,--user     user name of ssh, default root")
    print("       -w,--password password of ssh")
    print("       -p,--port     port of ssh")
    print("       exp: %s -i 127.0.0.1,192.168.1.3 -p 22" %(argv[0]))

def argv_parse(argv):
    opts, args = getopt.getopt(argv[1:], "f:i:u:w:p:", ["file=",'ips=', 'user=', 'password='])
    param = {'user':"root", 'password':'ruijie1688', 'ips':[], 'port':9622}
    if len(opts) == 0 and len(args):
        help(argv, param)
        return None
    for cmd, val in opts:
        if cmd in ('-f', '--file'):
            param['ips'] = read_hosts_on_file(val)
            continue
        if cmd in ('-i', '--ips'):
            param['ips'] = val.split(',')
            continue
        if cmd in ('-u', '--user'):
            param['user'] = val
            continue
        if cmd in ('-w', '--password'):
            param['password'] = val
            continue
        if cmd in ('-p', '--port'):
            param['port'] = int(val)
            continue
        help(argv, param)
        return None
    return param

def main(argv):
    try:
        param = argv_parse(argv)
        if param is None:
            help(argv, param)
            return
        t = multi_ssh(user = param['user'], host=param['ips'], password=param['password'], port=param['port'])
        if not t.run():
            help(argv, param)
    except Exception as e:
        print("main error: {0}".format(e))
    finally:
        print("exit.")

if __name__ == "__main__":
    main(sys.argv)
            
            