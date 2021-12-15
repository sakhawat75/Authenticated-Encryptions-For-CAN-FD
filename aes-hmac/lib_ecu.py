import sys
import threading
import socket, time
import select
import signal
from Crypto.Cipher import AES
import hmac
import hashlib
from ecdsa import SigningKey, VerifyingKey


class ecu(object):

    def __init__(self, identifier, message_type=None, security_keys=None, private_key=None, public_shared_keys=None, host='127.0.0.1', port=20202):

        # message_type
        #   None        - plain text - no signature or encryptyon
        #   symmetric   - uses aes-128 and hmac sha-256
        #   ecdsa       - assymetric signature
        self.message_type = message_type
        self.security_keys = security_keys
        # ECU Identifier
        self.identifier = identifier
        # Create ECU socket to connect to bus
        self.socket_open = False
        self.ClientSocket = None
        self.host = host
        self.port = port
        # self.block_size = AES.block_size
        self.block_size = 48                    # with max size of the message on bus - disconting hmac signature
        self.sleep_in_select = 1
        self.max_total_size = 64
        # ECDSA parameters
        self.private_key = private_key
        self.public_shared_keys = public_shared_keys
        self.signature_size = 40
        # Setting max size of the message
        self.max_payload_size = self.max_total_size
        if message_type == 'symmetric':
            self.max_payload_size = self.block_size - 1     # to have ate lest one byte of padding
        elif message_type == 'ecdsa':
            self.max_payload_size = self.max_total_size - self.signature_size
        self.exit = False
        self.line_separator = f"\n----------  ECU {self.identifier}  --------------------------------------\n" \
                              "- Type message to send.\n"\
                              "- or type exit to finnish\n"

    def embyulty_hex(self, msg):
        newlist = []
        if isinstance(msg, str):
            for c in msg:
                newlist.append(f"{ord(c):0=2X}")
        elif isinstance(msg, (bytearray, bytes)):
            for c in msg:
                newlist.append(f"{c:0=2X}")
        return ' '.join(newlist)

    def decrypt_and_show(self, Message_enc):
        # Start time
        start = time.time()
        if not self.message_type:
            print(
                f"Received message.\n"
                f"Identifier: {self.identifier}\n"
                f"Message in hexa: {self.embyulty_hex(Message_enc)}\n"
                f"Message: {Message_enc}\n"
            )
        elif self.message_type == 'symmetric':
            # Check authenticity
            msg_part = Message_enc[:self.block_size]
            sig = Message_enc[self.block_size:]
            dig = hmac.new(self.security_keys['hmac-sha-256'][:32].encode(), msg=msg_part, digestmod=hashlib.sha256).digest()
            # It is authentic
            decipher = AES.new(self.security_keys['aes-128'][:16], AES.MODE_ECB)
            decmsg = decipher.decrypt(msg_part)
            final_msg = self.__unpad(decmsg)
            print(
                f"Received message.\n"
                f"Identifier:      {self.identifier}\n"
                f"Complete message received    {self.embyulty_hex(Message_enc)}  Len:{len(Message_enc)}\n"
                f"HMAC calculated              {self.embyulty_hex(dig)}  Len:{len(dig)}\n"
                f"HMAC received part           {self.embyulty_hex(sig):>95}  Len:{len(sig)}\n"
                f"Engrypted Message:           {self.embyulty_hex(Message_enc[:len(decmsg)])}"
            )
            if dig[16:] != sig:
                print("HMAC     NOT     verified, Message Authentication Failed!")
            else:
                print("HMAC verified, Message Authentication is Successful!")
                print(
                    f"Decrypted Message in hexa:   {self.embyulty_hex(final_msg)}\n"
                    f"Decrypted Message            {final_msg}\n"
                )
        elif self.message_type == 'ecdsa':
            # Check authenticity
            sender = None
            signature = Message_enc[-self.signature_size:]
            all_message = Message_enc[:-self.signature_size]
            msg_md5 = hashlib.md5(all_message).digest()
            # Trying to findout the sender
            for k, v in self.public_shared_keys.items():
                pem = VerifyingKey.from_pem(v['signature_public'].decode())
                try:
                    if pem.verify(signature, msg_md5):
                        sender = k
                        break
                except Exception as e:
                    pass
            print(
                f"Received message.\n"
                f"Identifier:      {self.identifier}\n"
                f"Complete message received    {self.embyulty_hex(Message_enc)}  Len:{len(Message_enc)}\n"
                f"ECDSA received               {self.embyulty_hex(signature):>95}  Len:{len(signature)}\n"
                f"MD5 calculated               {self.embyulty_hex(msg_md5):>95}  Len:{len(msg_md5)}\n"
            )
            if not sender:
                print("Signature    NOT     verified, Message Authentication Failed!")
            else:
                print("Signature   verified, Message Authentication is Successful!\n"
                      f"            Received from    {sender}"
                      f"Message in hexa:             {self.embyulty_hex(all_message)}\n"
                      f"Message:                     {all_message}"
                )
        # Print execution time
        # print(f"Execution time: {time.time() - start} milliseconds")
        print(self.line_separator)

    def encypt_and_send(self, msg):
        msg_len = len(msg)
        if not self.message_type:
            self.ClientSocket.send(msg)
            print(f"Data has been sent!\n"
                  f"Identifier:      {self.identifier}\n"
                  f"Original Message:          {msg}\n"
                  f"Original Message to hexa:  {self.embyulty_hex(msg)}\n"
            )
        elif self.message_type == 'symmetric':
            cipher = AES.new(self.security_keys['aes-128'][:16], AES.MODE_ECB)
            encmsg = cipher.encrypt(self.__pad(msg))
            dig = hmac.new(self.security_keys['hmac-sha-256'][:32].encode(), msg=encmsg, digestmod=hashlib.sha256).digest()
            fullmsg = encmsg + dig[16:]
            self.ClientSocket.send(fullmsg)
            print(f"Data has been sent!\n"
                  f"Identifier:           {self.identifier}\n"
                  f"Original Message:                 {msg}\n"
                  f"Original Message to hexa:         {self.embyulty_hex(msg)}\n"
                  f"Encrypted message:                {self.embyulty_hex(encmsg[:msg_len])}\n"
                  f"Encrypted message with padding:   {self.embyulty_hex(encmsg[:self.block_size])}  Len:{self.block_size}\n"
                  f"HMAC calculated                   {self.embyulty_hex(dig)}  Len:{len(dig)}\n"
                  f"HMAC sent part                    {self.embyulty_hex(dig[16:]):>95}  Len:{len(dig[16:])}\n"
                  f"Complete message on bus           {self.embyulty_hex(fullmsg)}  Len:{len(fullmsg)}\n"
            )
        elif self.message_type == 'ecdsa':
            md5_msg = hashlib.md5(msg).digest()
            # create signature using md5 of the msg
            pem = SigningKey.from_pem(self.private_key.decode())
            signature = pem.sign_deterministic(md5_msg)
            fullmsg = msg + signature
            self.ClientSocket.send(fullmsg)
            print(f"Data has been sent!\n"
                  f"Identifier:           {self.identifier}\n"
                  f"Original Message:                 {msg}\n"
                  f"Original Message to hexa:         {self.embyulty_hex(msg)}\n"
                  f"ECDSA calculated                  {self.embyulty_hex(signature)}  Len:{len(signature)}\n"
                  f"MD% calculated                    {self.embyulty_hex(md5_msg)}  Len:{len(md5_msg)}\n"
                  f"Complete message on bus           {self.embyulty_hex(fullmsg)}  Len:{len(fullmsg)}\n"
            )

    def send_to_buss(self, msg):
        if not self.socket_open:
            print("Server is down")
            self.open_socket()
        else:
            while msg:
                msg_slice = msg[:self.max_payload_size].encode()
                msg = msg[self.max_payload_size:]
                # Send message
                self.encypt_and_send(msg_slice)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = bytearray(number_of_bytes_to_pad * ascii_string, 'ascii')
        # print(f"type plain {type(plain_text)}   {type(padding_str)}")
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    def __unpad(self, plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]

    def message_input(self):
        # Loop to way typing messages on keyboard and send to bus
        while True:
            print(self.line_separator)
            # Get input
            message = input("")
            if self.exit:
                break
            if message == 'exit':
                self.exit = True
                break
            if message:
                print("-----------------------------------------------")
                self.send_to_buss(message)

    # Receive function to receive messages from ECUs
    def receive_from_bus(self):
        # This is the thread processor
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
            rcvdata = None
            try:
                rcvdata = self.ClientSocket.recv(64)
            except Exception as e:
                print("Probably server is down")
                self.open_socket()
                continue
            if not rcvdata:
                print("Probably server is down")
                self.open_socket()
                continue
            self.decrypt_and_show(rcvdata)

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

    def proc(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        # Create a socket with bus
        if not self.open_socket():
            sys.exit(1)
        # create a thread to receive data in parallel with wayiting for user type message to send
        new_worker = threading.Thread(target=self.receive_from_bus)
        new_worker.start()
        self.message_input()
        new_worker.join()

    def signal_handler(self, sig, frame):
        print(self.line_separator)
        self.exit = True
        sys.exit(1)

