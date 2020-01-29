import os

DIR_PATH=os.path.dirname(os.path.realpath(__file__))
KEYS_DIR=os.path.join(DIR_PATH,'keys')
CERTS_DIR=os.path.join(DIR_PATH,'certs')
CC_CERTS_DIR=os.path.join(CERTS_DIR,'CCCerts')
CC_CRL_DIR=os.path.join(CERTS_DIR,'CCCRL')
SERVER_KEY=os.path.join(KEYS_DIR,'server.key')
