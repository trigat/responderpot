import argparse
import datetime
import random
import string
import sys
import time
import traceback
import smb
import smtplib
from smb.SMBConnection import SMBConnection

# This is a modified version of:
# https://github.com/benjaminkoffel/responderpot
# Logging and e-mail alerts have been added.
# Make sure LLMNR is turned on.

def sendmail(ip):
    send_address = 'sender@email.com'
    receive_address = 'receiver@email.com'
    message = 'Subject: Responder Detected\n\nThe use of Responder was detected at: ' + ip + '''
    Responder.py is an attacker tool that can answer LLMNR and NBT-NS queries giving its own IP address as the destination for any hostname requested.
    It will ask client machines for credentials.  If client machines are incorrectly configured, this can yield domain user/administrator hashes.'''

    with smtplib.SMTP("10.1.140.10", 25) as server:
        # server.starttls()
        # server.ehlo()
        # server.login(send_address, password)
        server.sendmail(send_address, receive_address, message)
        server.quit()

def randchars(mn, mx):
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in \
                range(random.randint(mn, mx)))

def logfile(ip):
    with open('log.txt', 'r+') as f:
        if any(ip in line for line in f):
            pass
        else:
            f.write(ip + '\n')
            print('Writing to log: ', ip)
            sendmail(ip)

def connect(domain, username, password, client, server):
    try:
        conn = SMBConnection(username, password, client, server, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
        conn.connect('collabshare', 445)
        ip, port = conn.sock.getpeername()
        conn.close()
        print('{} INFO SUSPICIOUS_SMB_RESPONSE {} {}'.format(str(datetime.datetime.now()), ip, port))
        logfile(ip)
    except smb.smb_structs.ProtocolError as e:
        ip, port = conn.sock.getpeername()
        conn.close()
        print('{} INFO SUSPICIOUS_SMB_RESPONSE {} {}'.format(str(datetime.datetime.now()), ip, port))
        logfile(ip)
    except ConnectionRefusedError as e:
        pass
    except Exception as e:
        sys.stderr.write('{} ERROR {}'.format(str(datetime.datetime.now()), traceback.format_exc()))

def monitor(domain, throttle):
    while True:
        connect(domain, randchars(6, 12), randchars(6, 12), randchars(6, 12), randchars(6, 12))
        time.sleep(throttle)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', '-d', default='WORKGROUP', help='target domain for monitoring')
    parser.add_argument('--throttle', '-t', type=int, default=10, help='throttle requests in seconds')
    args = parser.parse_args()
    monitor(args.domain, args.throttle)
