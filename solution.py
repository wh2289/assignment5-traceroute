from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
   ID = os.getpid() & 0xFFFF
   myChecksum = 0
   header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
   data = struct.pack("d", time.time())
   myChecksum = checksum(header+data)
   if sys.platform == 'darwin':
       myChecksum = htons(myChecksum) & 0xffff
   else:
       myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = []
    tracelist2 = []

    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)


            icmp = socket.getprotobyname("icmp")
            try:
                mySocket = socket(AF_INET, SOCK_RAW, icmp)
            except error as msg:
                print("Socket Error:", msg)

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:
                    tracelist1.append("* * * Request timed out.")
                    print("\t*\t\t*\t\t*\t\tRequest times out.")
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    print("\t*\t*\t*\Request timed out.")
            except timeout:
                continue

            else:
                ttl = recvPacket[8]
                type, pongCode, pongChecksum, pongID, pongSequence = struct.unpack("bbHHh", recvPacket[20:28])
                RTT = (timeReceived - struct.unpack("d", recvPacket[28:36])[0])*1000
                try:
                    routerHostname = gethostbyaddr(addr[0])[0]
                except herror:   #if the host does not provide a hostname
                    #Fill in start
                    #Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 +
                    bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here 
                    #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here and return your list if your destination IP is met
                    #Fill in end
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your list here
                    #Fill in end
                break
            finally:
                mySocket.close()

if __name__ == '__main__':
    get_route("google.co.il")