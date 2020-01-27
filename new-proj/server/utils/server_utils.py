import json
import struct

def send(conn, message):
        try:
            msg = json.dumps(message)
            conn.send((struct.pack('i', len(msg)) + bytes(msg, 'utf-8')))
        except OSError as e:
            print('OSError in send function @ utils.py')
            print(e)

def receive(conn):
        try:
            size = struct.unpack('i', conn.recv(struct.calcsize('i')))[0]
            data = ''
            while len(data) < size:
                msg = conn.recv(size - len(data))
                if not msg:
                    return None
                data += str(msg, 'utf-8')
            return data.strip()
        except OSError as e:
            print('OSError in receive function @ utils.py')
            print (e)