package com.packetanalyzer.pcap;

/**
 * Per-packet header (16 bytes) that precedes each packet's data in a .pcap file.
 * Translated from C++ struct PcapPacketHeader in pcap_reader.h
 */
public class PcapPacketHeader {

    public long tsSec;    // uint32_t: timestamp seconds
    public long tsUsec;   // uint32_t: timestamp microseconds
    public long inclLen;  // uint32_t: number of bytes saved in file
    public long origLen;  // uint32_t: actual length of the original packet
}
