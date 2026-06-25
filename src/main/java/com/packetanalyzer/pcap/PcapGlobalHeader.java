package com.packetanalyzer.pcap;

/**
 * PCAP global file header (first 24 bytes of every .pcap file).
 * Translated from C++ struct PcapGlobalHeader in pcap_reader.h
 *
 * All fields stored as long/int to handle unsigned values correctly.
 */
public class PcapGlobalHeader {

    public long magicNumber;   // uint32_t: 0xa1b2c3d4 (native) or swapped
    public int  versionMajor;  // uint16_t: usually 2
    public int  versionMinor;  // uint16_t: usually 4
    public int  thisZone;      // int32_t:  GMT offset (usually 0)
    public long sigFigs;       // uint32_t: accuracy of timestamps (usually 0)
    public long snapLen;       // uint32_t: max captured packet length
    public long network;       // uint32_t: data link type (1 = Ethernet)
}
