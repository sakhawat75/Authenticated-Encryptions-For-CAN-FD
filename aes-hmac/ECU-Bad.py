import sys
import socket, time
import select
import signal
import random


class ecu_bad(object):

    def __init__(self, identifier, host='127.0.0.1', port=20202):

        # ECU Identifier
        self.identifier = identifier
        # Create ECU socket to connect to bus
        self.socket_open = False
        self.ClientSocket = None
        self.host = host
        self.port = port
        self.sleep_in_select = 1
        self.max_total_size = 64
        self.exit = False
        self.line_separator = f"\n----------  ECU {self.identifier}  --------------------------------------\n" \
                              "- This is a Bad Device.\n"\
                              "- ^C to exit\n"

    def embyulty_hex(self, msg):
        newlist = []
        if isinstance(msg, str):
            for c in msg:
                newlist.append(f"{ord(c):0=2X}")
        elif isinstance(msg, (bytearray, bytes)):
            for c in msg:
                newlist.append(f"{c:0=2X}")
        return ' '.join(newlist)

    def proc(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        # Create a socket with bus
        if not self.open_socket():
            sys.exit(1)
        # create a thread to receive data in parallel with wayiting for user type message to send
        self.loop_on_bus()

    def signal_handler(self, sig, frame):
        print(self.line_separator)
        self.exit = True
        sys.exit(1)

    def open_socket(self):
        if self.socket_open:
            self.ClientSocket.close()
            self.socket_open = False
        try:
            self.ClientSocket = socket.socket()
            self.ClientSocket.connect((self.host, self.port))
            self.socket_open = True
        except Exception as e:
            print(f"Error trying to connect to host {self.host}:{self.port} ")
            return False
        return True

    def loop_on_bus(self):
        # This is the thread processor
        print(self.line_separator)
        while True:
            # Receive the encrypted message
            to_read = []
            if self.socket_open:
                to_read = [self.ClientSocket]
            readable, writable, exceptional = select.select(to_read, [], [], self.sleep_in_select)
            # print(f"{readable} {writable} {exceptional}")
            if not self.socket_open:
                self.open_socket()
                continue
            if self.exit:
                break
            if not readable:
                continue
            try:
                rcvdata = self.ClientSocket.recv(4096)
            except Exception as e:
                print("Probably server is down")
                self.open_socket()
                continue
            if not rcvdata:
                print("Probably server is down")
                self.open_socket()
                continue
            print(f"Message readed from bus:     {self.embyulty_hex(rcvdata)}  Len:{len(rcvdata)}")
            tosend = bytearray(rcvdata)
            idx = random.randint(0, len(rcvdata) - 1)
            newval = tosend[idx]
            while newval == tosend[idx]:
                newval = random.randint(0, 255)
            tosend[idx] = newval
            print(f"Message changed and resent:  {self.embyulty_hex(tosend)}  Len:{len(tosend)}")
            print(f"Replace byte in position     {idx} to val {newval:0=2X}")
            self.ClientSocket.send(tosend)
            print(self.line_separator)


identifier = sys.argv[0]
ecu = ecu_bad(identifier)
ecu.proc()
