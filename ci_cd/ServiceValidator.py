import socket
import time
import requests
import argparse


class ServiceValidator(object):
    def __init__(self):
        pass

    def verify_service_ready(self, host, port=None, web=True):
        if web:
            max_tries = 120  # 20 minutes
            verified = False
            tot_tries = 0
            while not verified:
                try:
                    response = requests.get(host)
                    if response.status_code == 200 or response.status_code == 302:
                        verified = True
                    else:
                        time.sleep(10)
                except:
                    time.sleep(10)
                tot_tries += 1
                if tot_tries >= max_tries:
                    return False
            return verified
        else:
            port = int(port)
            max_tries = 120  # 20 minutes
            verified = False
            tot_tries = 0
            while not verified:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        verified = True
                    sock.close()
                except socket.error:
                    time.sleep(10)
                tot_tries += 1
                if tot_tries >= max_tries:
                    return False
                time.sleep(10)
            return verified


if __name__ == '__main__':
    arg_desc = 'Run in CI/CD Pipeline'
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=arg_desc)
    parser.add_argument("-ip", "--iporhost", metavar="HOST", help="The IP or Hostname of the Service")
    parser.add_argument("-p", "--port", metavar="PORT", help="The TCP Port for the Service", default=None)
    parser.add_argument("-t", "--tcp", metavar="TCP", help="Whether or not to run TCP Scan (y or n)", default='n')
    args = vars(parser.parse_args())
    if args['port']:
        port = args['port']
    else:
        port = None
    if args['tcp'] == 'y':
        web = False
    else:
        web = True
    response = ServiceValidator().verify_service_ready(host=args['iporhost'], port=port, web=web)
    if response:
        print('Passed')
