#!usr/bin/env python3
import argparse , socket , struct , random , uuid

MAX_BYTES=65535

def getMacInByte():
    mac=str(hex(uuid.getnode()))
    mac = mac[2:]
    while len(mac) < 12:
        mac='0'+mac
    macb=b''
    for i in range( 0 , 12 , 2):
        m=int(mac[i:i+2],16)
        macb+=struct.pack('!B',m)
    return macb

class DHCPDiscover:
    def __init__(self):
        self.transID = b''
        for i in range(4):
            t=random.randint(0 , 255)
            self.transID+=struct.pack('!B',t)

    def build(self):
        macb    = getMacInByte()
        #Main Package payload 240 byte
        packet  = b''
        packet += b'\x01'                 # OPCode: Boot Request
        packet += b'\x01'                 # HType: Ethernet=1
        packet += b'\x06'                 # Length of mac 6 byte
        packet += b'\x00'                 # Hops: init set to 0
        packet += self.transID            # Transaction ID
        packet += b'\x00\x00'             # Secs
        packet += b'\x80\x00'             # Flags
        packet += b'\x00'*4               # Client IP
        packet += b'\x00'*4               # Distribute IP
        packet += b'\x00'*4               # SIADDR
        packet += b'\x00'*4               # GIADDR
        packet += macb                    # 48bit(6byte) Ethernet Addr
        packet += b'\x00'*10              # Padding Ethernet addr
        packet += b'\x00'*192             # BOOTP legacy
        packet += b'\x63\x82\x53\x63'     # Magic cookie: DHCP

        packet += b'\x35\x01\x01'         # Option53: length 1 , type 1 DHCP Discover
        packet += b'\x3d\x06'+macb        # Option61: Client identifier (MAC addr)
        packet += b'\x37\x03\x03\x01\x06' # Option55: length 3 , Parameter Request List
        packet += b'\xff'
        return packet

def server(port):
    dsocket=socket.socket(socket.AF_INET , socket.SOCK_DGRAM)
    dsocket.setsockopt(socket.SOL_SOCKET , socket.SO_BROADCAST, 1)
    dsocket.bind(('',67))
    print('Listening at {}'.format(dsocket.getsockname()))
    while True:
        data , address = dsocket.recvfrom(MAX_BYTES)
        offerAddr=b'\xc0\xa8'
        for i in range(2):
            t=random.randint(0,255)
            offerAddr+=struct.pack('!B',t)
        data=data[0:240]

def client(port):
    print("Client")
    dsocket=socket.socket(socket.AF_INET , socket.SOCK_DGRAM)
    dsocket.setsockopt(socket.SOL_SOCKET , socket.SO_BROADCAST, 1)

    try:
        dsocket.bind(('' , port))
    except Exception as e:
        print('port {} in used'.format(port))
        dsocket.close()
        input('Press any key to quit')
        exit()

    discoverPackage=DHCPDiscover()
    dsocket.sendto(discoverPackage.build() , ('<broadcast>', 67))
    print('DHCP Discover has sent. Wating for reply...\n')

if  __name__ == '__main__':
    choice={'client':client , 'server':server}
    parser = argparse.ArgumentParser(description='DHCP Implement')
    parser.add_argument('role', choices = choice , help='which role to play')
    parser.add_argument('-p' , metavar='PORT' , type=int , default=68 , help='DHCP default port')
    args=parser.parse_args()
    function=choice[args.role]
    function(args.p)
