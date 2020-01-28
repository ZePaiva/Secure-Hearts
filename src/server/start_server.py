# arguments parser
import argparse
import traceback

# server 
from server import SecureServer

# arguments
ap=argparse.ArgumentParser()
ap.add_argument("-L", "--logLevel", required=False, help="logging level")
ap.add_argument("-H", "--host", required=False, help="IP address for server")
ap.add_argument("-P", "--port", required=False, help="PORT for server")
ap.add_argument("-T", "--tables", required=False, help="number of tables")

sec_server=None

def main():
    global PORT
    global SERV
    global sec_server

    args = vars(ap.parse_args())
    if args['port']:
        PORT=args['port']
    else:
        PORT=8080

    if args['host']:
        SERV=args['host']
    else:
        SERV='127.0.0.1'

    if args['logLevel']:
        LOG=args['logLevel']
    else:
        LOG='INFO'

    if args['tables']:
        TABLES=args['tables']
    else:
        TABLES=4

    while True:
        try:
           sec_server=SecureServer(SERV, PORT, LOG, TABLES)
           sec_server.run()
        except KeyboardInterrupt as e:
            try:
                sec_server.pause()
            except KeyboardInterrupt as e:
                sec_server.exit()
                break
        except Exception as e:
            if sec_server is not (None):
                sec_server.emergency_exit(e)
            exit(1)

if __name__=="__main__":
    main()
