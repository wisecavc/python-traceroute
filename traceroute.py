# Author: Cade Wisecaver
# Date: 8/14/2024

import os
from socket import *
import struct
import time
import select

class IcmpHelperLibrary:

    class IcmpPacket:
        
        # scope variables
        __icmpTarget = ""               # remote Host
        __destinationIpAddress = ""     # remote Host IP Address
        __header = b''                  # header after byte packing
        __data = b''                    # data after encoding
        __dataRaw = ""                  # raw string data before encoding

        # valid values for the following variables are 0-255 (unsigned int, 8 bits)
        __icmpType = 0                  
        __icmpCode = 0                  

        # Valid values for the following variables are are 0-65535 (unsigned short, 16 bits)
        __packetChecksum = 0            
        __packetIdentifier = 0          
        __packetSequenceNumber = 0      

        __ipTimeout = 30
        __ttl = 255                     # time to live
        __dropped = True                # tracks if a packet was dropped or not
        __rtt = 0                       # tracks RTT of a single packet

        __DEBUG_IcmpPacket = False      # allows for debug output

        # IcmpPacket class getters
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getDropped(self):
            """Returns the value that keeps track of whether or not the packet was dropped"""
            return self.__dropped
        
        def getRTT(self):
            """Returns the round trip time (RTT) of the packet"""
            return self.__rtt
        
        # ### end section written by wisecavc ### #

        # icmpPacket class setters
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setDropped(self, booleanValue):
            """Sets the value that keeps track of whether or not the packet was dropped"""
            self.__dropped = booleanValue

        def setRTT(self, rtt):
            """Sets the round trip time (RTT) of the packet"""
            self.__rtt = rtt

        # IcmpPacket class private functions
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # this checksum function will work with pairs of values with two separate 16 bit segments.
            # any remaining 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # add 1's complement rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # rotate and add

            answer = ~checksum                  # invert bits
            answer = answer & 0xffff            # trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # type = 8 bits
            # code = 8 bits
            # ICMP header checksum = 16 bits
            # identifier = 16 bits
            # sequence number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # result will set new checksum value
            self.__packHeader()                 # header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):

            # maintains a truth table for the state of verification for each of the 3 tested characteristics
            # [0] tracks sequence number, [1] tracks identifier, [2] tracks raw data
            truth_list = [False, False, False]

            # tracks the sequence number for use in debugging messages showing expected and actual values
            icmpReplyPacket.set_SeqNum_sent(self.getPacketSequenceNumber())

            if self.__DEBUG_IcmpPacket:  # immediate comparison used for debugging
                print('Recieved Icmp sequence number: ' + str(icmpReplyPacket.getIcmpSequenceNumber()))
                print('Sent packet sequence number: ' + str(self.getPacketSequenceNumber()))

            # if sequence number received is the same as sequence number sent
            if icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber():

                # records that the sequence number is valid in the truth table
                icmpReplyPacket.setSequenceNumber_isValid(True)
                truth_list[0] = icmpReplyPacket.getSequenceNumber_isValid()

                if self.__DEBUG_IcmpPacket:  # immediate feedback for use in debugging
                    print('# Identical? ' + str(icmpReplyPacket.getSequenceNumber_isValid()))
            else:
                if self.__DEBUG_IcmpPacket:
                    print('\nWarning: sent packet sequence number does NOT match recieved icmp sequence number')

            # tracks the identifier for use in debugging messages showing expected and actual values
            icmpReplyPacket.set_identifier_sent(self.getPacketIdentifier())

            if self.__DEBUG_IcmpPacket:  # immediate comparison used for debugging
                print('Received Icmp identifier: ' + str(icmpReplyPacket.getIcmpIdentifier()))
                print('Sent packet identifier: ' + str(self.getPacketIdentifier()))

            # records that the identifier is valid in the truth table
            if icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier():
                icmpReplyPacket.setIdentifier_isValid(True)
                truth_list[1] = icmpReplyPacket.getIdentifier_isValid()

                if self.__DEBUG_IcmpPacket:  # immediate comparison used for debugging
                    print('# Identical? ' + str(icmpReplyPacket.getIdentifier_isValid()))
            else:
                if self.__DEBUG_IcmpPacket:
                    print('\nWarning: sent packet identifier does NOT match recieved icmp identifier')

            # tracks the identifier for use in debugging messages showing expected and actual values
            icmpReplyPacket.set_data_sent(self.getDataRaw())

            if self.__DEBUG_IcmpPacket:  # immediate comparison used for debugging
                print('Recieved Icmp raw data: ' + str(icmpReplyPacket.getIcmpData()))
                print('Sent packet raw data: ' + str(self.getDataRaw()))

            # records that the identifier is valid in the truth table
            if icmpReplyPacket.getIcmpData() == self.getDataRaw():
                icmpReplyPacket.setData_isValid(True)
                truth_list[2] = icmpReplyPacket.getData_isValid()

                if self.__DEBUG_IcmpPacket:  # immediate comparison used for debugging
                    print('# Identical? ' + str(icmpReplyPacket.getData_isValid()))
            else:
                if self.__DEBUG_IcmpPacket:
                    print('\nWarning: sent packet raw data does NOT match recieved icmp raw data')

            # sets valid response to True if all tests returned True
            icmpReplyPacket.setIsValidResponse(all(truth_list))
            if self.__DEBUG_IcmpPacket:
                print('\n##########',
                      'Is the echo reply valid? ',
                      str(icmpReplyPacket.isValidResponse()),
                      '##########\n')
            
            return icmpReplyPacket.isValidResponse()

        # IcmpPacket Class Public Functions
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            # reformatted output message
            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress + '\n')

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                rtt = (timeReceived - pingStartTime) * 1000  # defines RTT for every packet sent

                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    rtt,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )
                        
                        # handles error type returns for objective 4 in assignment description
                        type_11_err_codes = {
                            0 : 'Time to Live exceeded in Transit',
                            1 : 'Fragment Reassembly Time Exceeded'
                        }

                        print('IMCP Response Error 11, Code ' + str(icmpCode) + ' detected. ',
                              'Error message: Time Exceeded; ' + type_11_err_codes[icmpCode])

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      rtt,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        
                        # handles error type returns for objective 4 in assignment description
                        type_3_err_codes = {
                            0 : 'Net Unreachable',
                            1 : 'Host Unreachable',
                            2 : 'Protocol Unreachable',
                            3 : 'Port Unreachable',
                            4 : "Fragmentation Needed and Don't Fragment was Set",
                            5 : "Source Route Failed",
                            6 : 'Destination Network Unknown',
                            7 : 'Destination Host Unknown',
                            8 : 'Source Host Isolated',
                            9 : 'Communication with Destination Network is Administratively Prohibited',
                            10 : 'Communication with Destination Host is Administratively Prohibited',
                            11 : 'Destination Network Unreachable for Type of Service',
                            12 : 'Destination Host Unreachable for Type of Service',
                            13 : 'Communication Administratively Prohibited',
                            14 : 'Host Precedence Violation',
                            15 : 'Precedence cutoff in effect'
                        }

                        print('IMCP response Error 3, Code ' + str(icmpCode) + ' detected. ',
                              'Error message: Destination Unreachable; ' + type_3_err_codes[icmpCode])

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)

                        # validates packet info with icmp info to determine if the packet is dropped
                        if self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket):
                            self.setDropped(False)

                        self.setRTT(icmpReplyPacket.getRTT(timeReceived))  # tracks each packet's RTT

                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)

                        return     # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    class IcmpPacket_EchoReply:
        
        # scope variables
        __recvPacket = b''
        __isValidResponse = False

        # added validity flags
        __identifier_isValid = False
        __sequenceNumber_isValid = False
        __data_isValid = False

        # added important packet original values to track between classes
        __original_SeqNum = None
        __original_identifier = None
        __original_data = None

        # IcmpPacket_EchoReply Constructors
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # IcmpPacket_EchoReply Getters
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # IcmpPacket_EchoReply Setters
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # set/get functions for the added validity flags and original packet values

        def getData_isValid(self):
            return self.__data_isValid

        def setData_isValid(self, booleanValue):
            self.__data_isValid = booleanValue

        def set_data_sent(self, data):
            self.__original_data = data

        def get_data_sent(self):
            return self.__original_data

        def getIdentifier_isValid(self):
            return self.__identifier_isValid

        def setIdentifier_isValid(self, booleanValue):
            self.__identifier_isValid = booleanValue

        def set_identifier_sent(self, id):
            self.__original_identifier = id

        def get_identifier_sent(self):
            return self.__original_identifier

        def getSequenceNumber_isValid(self):
            return self.__sequenceNumber_isValid

        def setSequenceNumber_isValid(self, booleanValue):
            self.__sequenceNumber_isValid = booleanValue

        def set_SeqNum_sent(self, sq):
            self.__original_SeqNum = sq

        def get_SeqNum_sent(self):
            return self.__original_SeqNum

        # IcmpPacket_EchoReply Private Functions
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # IcmpPacket_EchoReply Public Functions
        def getRTT(self, timeReceived):
            """Gets round trip time by extracting the timestamp from received packet to compare with time received
            Code borrowed from the function below, printResultToConsole"""
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            return (timeReceived - timeSent) * 1000
        
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            
            # States whether the received echo response Icmp is confirmed as valid when compared to the sent packet
            print('Echo response validity: ' + str(self.isValidResponse()))

            if not self.isValidResponse():
                print('Checking for errors...')
                # if sequence numbers were different
                if not self.getSequenceNumber_isValid():
                    print('Icmp sequence number does not match sequence number of packet sent!')
                    print('Packet sequence number: ' + str(self.get_SeqNum_sent()))
                    print('Icmp sequence number: ' + str(self.getIcmpSequenceNumber()))
                # if identifiers were different
                if not self.getIdentifier_isValid():
                    print('Icmp identifier does not match identifier of packet sent!')
                    print('Packet identifier: ' + str(self.get_identifier_sent()))
                    print('Icmp identifier: ' + str(self.getIcmpIdentifier()))
                # if raw data was different
                if not self.getData_isValid():
                    print('Icmp data does not match data of packet sent!')
                    print('Packet data: ' + str(self.get_data_sent()))
                    print('Icmp data: ' + str(self.getIcmpData()))

    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # IcmpHelperLibrary Private Functions
    def __sendIcmpEchoRequest(self, host, ttl=4, traceroute=False):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # for calculating final statistics relating to rtt and percent of packets dropped
        max_rtt = 0
        min_rtt = float('inf')
        rtt_count = []
        dropped_count = []

        # range was originally 4, ttl was implemented for use when performing a traceroute
        # range reverts to 4 when a ping is sent instead
        for i in range(ttl):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            if traceroute:  # sets TTL in accordance with the current hop of the traceroute
                icmpPacket.setTtl(i)

            icmpPacket.sendEchoRequest()                                                # Build IP

            # gets data for each packet's RTT and dropped status
            rtt = icmpPacket.getRTT()
            was_dropped = icmpPacket.getDropped()

            if rtt is not None:  # handles RTT min and max, and collects individual packet RTTs
                if rtt > max_rtt:
                    max_rtt = rtt
                if rtt < min_rtt:
                    min_rtt = rtt
                rtt_count.append(rtt)

            # collects individual packet's dropped status
            dropped_count.append(was_dropped)

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # returns final RTT stats of all packets sent in a ping (collectively)
        print('\nMaximum RTT: ' + str(max_rtt))
        print('Minimum RTT: ' + str(min_rtt))
        print('Average RTT: ' + str(sum(rtt_count) / len(rtt_count)))

        # returns final stats of how many packets were dropped. Higher % means more dropped packets
        if not any(dropped_count):
            percent_dropped = '0%'
        else:
            percent_dropped = str((dropped_count.count(True) / len(dropped_count)) * 100) + '%'
        print('Percentage of packets lost: ' + percent_dropped)

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

        hops = 50  # sets default number of hops to be made in traceroute

        # starts an echo request to carry out traceroute
        # executed very similarly to the ping method, only with varying TTL
        self.__sendIcmpEchoRequest(host, hops, True)

    # IcmpHelperLibrary Public Functions
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)

def main():
    icmpHelperPing = IcmpHelperLibrary()

    # ############################################################################################################ #
    # Examples of Functionality - Choose one of the following by uncommenting out the line                         #
    #                                                                                                              #
    #                                                                                                              #
    #                                                                                                              #
    #                                                                                                              #
    # ############################################################################################################ #

    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")

    # Type 3 errors:
    # icmpHelperPing.traceRoute("200.10.227.250")

    # Different continents:
    # icmpHelperPing.traceRoute("www.chinaunicom.com")  # China
    # icmpHelperPing.traceRoute("moov-africa.bf")  # Africa

    # icmpHelperPing.traceRoute("www.google.com")


if __name__ == "__main__":
    main()
