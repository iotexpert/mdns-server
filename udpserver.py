import socket
import struct
import ctypes
from enum import Enum

localPort   = 5353
bufferSize  = 1024


class dnsHeader(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [    ("id",ctypes.c_uint,16),
                    ("qr",ctypes.c_uint,1),
                    ("opcode",ctypes.c_uint,4),
                    ("aa",ctypes.c_uint,1),
                    ("tc",ctypes.c_uint,1),
                    ("rd",ctypes.c_uint,1),
                    ("ra",ctypes.c_uint,1),
                    ("z",ctypes.c_uint,3),
                    ("rcode",ctypes.c_uint,4),
                    ("qdcount",ctypes.c_uint16),
                    ("ancount",ctypes.c_uint16),
                    ("nscount",ctypes.c_uint16),
                    ("arcount",ctypes.c_uint16),
    ]

    qrText = {0:"Query",1:"Response"}
    opcodeText = {0:"Query",1:"IQuery",2:"Status",3:"reserved",4:"Notify",5:"Update"}
    aaText = {0:"Non Authoratative",1:"Authoratative"}
    tcText = {0:"No Truncation",1:"Truncation"}
    rdText = {0:"No Recursion",1:"Recursion"}
    raText = {0:"No Recursion Available",1:"Recursion Available"}
    zText = {0:"Reserved"}
    rcodeText = {
        0:"No Error",
        1:"Format Error",
        2:"Server Failure",
        3:"Name Error",
        4:"Not implemented",
        5:"Refused - probably a policy reason",
        6:"A name exists when it should not",
        7:"a resource record set exists that should not",
        8:"NX RR Set - A resource record set that should exist does not",
        9:"Not Authorized",
        10:"Not Zone",
    }

    def printHeader(self):
        print(f"id = {self.id}")
        print(f"qr = {self.qr} {self.qrText.get(self.qr,'Unknown')}")
        print(f"opcode = {self.opcode} {self.opcodeText.get(self.opcode,'Unknown')}")
        print(f"aa = {self.aa} {self.aaText.get(self.aa,'Unknown')}")
        print(f"tc = {self.tc} {self.tcText.get(self.tc,'Unknown')}")
        print(f"rd = {self.rd} {self.rdText.get(self.rd,'Unknown')}")
        print(f"ra = {self.ra} {self.raText.get(self.ra,'Unknown')}")
        print(f"z = {self.z} {self.zText.get(self.z,'Unknown')}")
        print(f"response code = {self.rcode} {self.rcodeText.get(self.rcode,'Unknown')}")
        print(f"Question count = {self.qdcount}")
        print(f"Answer count = {self.ancount}")
        print(f"Name server count = {self.nscount}")
        print(f"Additional record count = {self.arcount}")



class ResourceRecordType(Enum):
    Question = 0
    Answer = 1
    NameServer = 2
    AdditionalRecords = 3

class ResourceRecordHeader(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("type"     ,ctypes.c_uint16),
        ("dnsclass"    ,ctypes.c_uint16),
        ("ttl"      ,ctypes.c_uint32),
        ("rdlength" ,ctypes.c_uint16),
    ]

    def printHeader(self):
        print(f"Type = {self.type:x}")
        print(f"Class = {self.dnsclass:x}")
        print(f"TTL = {self.ttl:x}")
        print(f"Length = {self.rdlength:x}")

class QuestionRecordHeader(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("type"     ,ctypes.c_uint16),
        ("dnsclass"    ,ctypes.c_uint16),
    ]

    def printHeader(self):
        print(f"Type = {self.type:x}")
        print(f"Class = {self.dnsclass:x}")


'''
 TypeMap = [
     1:"A",
     2:"NS",
     3:"MD",
     4:"MF",
     5:"CNAME",
     6:"SOA",
     7:"MB",
     8:"MG",
     9:"MR",
     10:"NULL",
     11:"WKS",
     12:"PTR",
     13:"HINFO",
     14:"MXINFO",
     15:"MX",
     16:"TXT",
 ]
'''


class ResourceRecord:
    def __init__(self,type,offset,message,pnlist):
        print(f"Starting Resource Record at offset={offset} 0x{offset:X}")
        self.type = type
        self.length = 0
        self.name = []
        self.partialNames = pnlist
        self.processNames(message,offset)
        
        if type == ResourceRecordType.Question:
            self.header = QuestionRecordHeader.from_buffer_copy(message[self.length-1:])
            self.length += ctypes.sizeof(self.header)
        else:
            self.header = ResourceRecordHeader.from_buffer_copy(message[self.length-1:])
            self.length += ctypes.sizeof(self.header)

            self.data = message[self.length-1 :self.length-1 + self.header.rdlength]
            print(f"Data Start = {self.length-1} Data End={self.length-1 + self.header.rdlength}")
            print(f"Length of Data = {self.header.rdlength}")
            print(f"Data = {bytes(self.data)}")

            self.length += self.header.rdlength

        
        print(f"Total Length = {self.length}")
        print(f"Name = {self.name}")
    
    def processNames(self,message,offset):
        currentPos = 0
        while True:
            count = message[currentPos]
            currentPos = currentPos + 1

            if count & 0b11000000:
                ptr = (count & ~0b11000000)<<8 | message[currentPos]
                self.partialNames.append((ptr,"Pointer"))
                print(f"Pointer {count:x} {message[currentPos]:x} {ptr}")
                currentPos = currentPos + 2
                break

            elif count>0:
                name = str(message[currentPos:currentPos+count])
                self.partialNames.append((offset+currentPos-1,name))
                self.name.append(name)
                print(f"Name:{name} Len = {len(name)} count={count}")    
                currentPos = currentPos + count
            
            else:
                currentPos += 1
                print("Breaking")
                break

            print(f"CurrentPos = {currentPos}")


        self.length += currentPos
        print(f"Length = {self.length} currentPos = {currentPos}")



# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

# Bind to address and ip
UDPServerSocket.bind(('', localPort))

mreq = struct.pack("4sl", socket.inet_aton('224.0.0.251'), socket.INADDR_ANY)
UDPServerSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print("UDP server up and listening")

# Listen for incoming datagrams
while(True):

    print("------------------------------------------------------------------------------")
    (message, address) = UDPServerSocket.recvfrom(bufferSize)

    clientMsg = "Message from Client:{}".format(message)
    clientIP  = "Client IP Address:{}".format(address)
    print(clientIP)

    dnsh = dnsHeader.from_buffer_copy(message)
    dnsh.printHeader()


# Print the HEX & ASCII of the message
    count = 0
    stepSize = 16
    for i in range(0,len(message),stepSize):
        if i + stepSize > len(message):
            count = len(message) - i
        else:
            count = stepSize

        print(f'{i:04X}',end=" ")

        for j in range(count):
            print(f'{message[j+i]:02X}', end=" ")
        
        if stepSize != count:
            for i in range(stepSize - count):
                print("-- ",end="")

        for j in range(count):
            if message[j+i] >= 32 and message[j+i]<=127:
                print(f'{message[j+i]:c}', end="")
            else:
                print("-",end="")

        print("")

    

# Decode Name which is variable length

    offset = 12

# print the name section of the resource record
    partialNames = []

    for i in range(dnsh.qdcount):
        print(f"Processing Question {i}")
        rr = ResourceRecord(ResourceRecordType.Question,offset,message[offset:],partialNames)
        partialNames.append(rr.partialNames)
        offset = offset + rr.length - 1
        rr.header.printHeader()

        print(f"Current Offset = {offset}")
        print("")
        print("")

    for i in range(dnsh.ancount):
        print(f"Processing Answer {i}")
        rr = ResourceRecord(ResourceRecordType.Answer,offset,message[offset:],partialNames)
        offset = offset + rr.length - 1
        partialNames.append(rr.partialNames)

        rr.header.printHeader()
        
        print(f"Current Offset = {offset}")
        print("")
        print("")

    for i in range(dnsh.nscount):
        print(f"Processing Name Server {i}")
        rr = ResourceRecord(ResourceRecordType.NameServer,offset,message[offset:],partialNames)
        offset = offset + rr.length - 1
        partialNames.append(rr.partialNames)

        rr.header.printHeader()
        print(f"Current Offset = {offset}")
        print("")
        print("")



    for i in range(dnsh.arcount):
        print(f"Processing Additional Records {i}")
        rr = ResourceRecord(ResourceRecordType.AdditionalRecords,offset,message[offset:],partialNames)
        offset = offset + rr.length - 1
        rr.header.printHeader()
        print(f"Current Offset = {offset}")
        print("")
        print("")


    print(f"Partial Name = {partialNames}")