package com.packetanalyzer.parser;

/**
 * Parsed, human-readable representation of a single network packet.
 * Translated from C++ struct ParsedPacket in packet_parser.h
 *
 * C++ raw pointers (payload_data) are replaced with an offset+length pair
 * pointing into the original RawPacket data array.
 */
public class ParsedPacket {

    // Timestamps
    public long   timestampSec;
    public long   timestampUsec;

    // Ethernet layer
    public String srcMac;
    public String destMac;
    public int    etherType;   // uint16_t stored as int

    // IP layer
    public boolean hasIp      = false;
    public int     ipVersion;
    public String  srcIp;
    public String  destIp;
    public int     protocol;   // uint8_t: TCP=6, UDP=17, ICMP=1
    public int     ttl;        // uint8_t

    // Transport layer
    public boolean hasTcp  = false;
    public boolean hasUdp  = false;
    public int     srcPort;    // uint16_t
    public int     destPort;   // uint16_t

    // TCP-specific
    public int  tcpFlags;   // uint8_t
    public long seqNumber;  // uint32_t
    public long ackNumber;  // uint32_t

    // Payload — expressed as offset + length into the original data[] array
    public int     payloadOffset;
    public int     payloadLength;
    public byte[]  payloadData;  // Direct reference to raw packet data slice
}
