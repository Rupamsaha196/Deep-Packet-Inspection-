package com.packetanalyzer.pcap;

/**
 * Represents a single captured raw packet (header + data bytes).
 * Translated from C++ struct RawPacket in pcap_reader.h
 */
public class RawPacket {

    public PcapPacketHeader header = new PcapPacketHeader();
    public byte[]           data;   // The actual packet bytes (was std::vector<uint8_t>)
}
