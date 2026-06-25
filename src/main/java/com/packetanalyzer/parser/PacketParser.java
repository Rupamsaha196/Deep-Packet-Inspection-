package com.packetanalyzer.parser;

import com.packetanalyzer.pcap.RawPacket;

/**
 * Parses a raw PCAP packet into its layer-by-layer components.
 * Translated from C++ class PacketParser in packet_parser.h / packet_parser.cpp
 *
 * Key translation notes:
 *  - All ntohs/ntohl calls replaced by manual big-endian byte extraction
 *  - reinterpret_cast replaced by ByteBuffer or direct byte indexing
 *  - uint8_t/uint16_t handled by masking: & 0xFF, & 0xFFFF
 */
public class PacketParser {

    // Protocol numbers (was namespace Protocol in packet_parser.h)
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // EtherType values (was namespace EtherType in packet_parser.h)
    public static final int ETHER_IPv4 = 0x0800;
    public static final int ETHER_IPv6 = 0x86DD;
    public static final int ETHER_ARP  = 0x0806;

    // TCP Flag bits (was namespace TCPFlags in packet_parser.h)
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Parse a raw packet into its layer fields.
     * Translated from PacketParser::parse() in packet_parser.cpp
     *
     * @param raw    the raw PCAP packet
     * @param parsed output object to fill (reset before use)
     * @return true if parsing succeeded
     */
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        // Reset all fields
        resetParsed(parsed);
        parsed.timestampSec  = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int    len  = data.length;
        int[]  offsetHolder = {0}; // Use array to pass offset by reference

        // Parse Ethernet header
        if (!parseEthernet(data, len, parsed, offsetHolder)) {
            return false;
        }

        // Parse IP layer for IPv4 packets
        if (parsed.etherType == ETHER_IPv4) {
            if (!parseIPv4(data, len, parsed, offsetHolder)) {
                return false;
            }

            // Parse transport layer
            if (parsed.protocol == PROTO_TCP) {
                if (!parseTCP(data, len, parsed, offsetHolder)) {
                    return false;
                }
            } else if (parsed.protocol == PROTO_UDP) {
                if (!parseUDP(data, len, parsed, offsetHolder)) {
                    return false;
                }
            }
        }

        // Set payload information
        int offset = offsetHolder[0];
        if (offset < len) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = len - offset;
            parsed.payloadData   = data; // Reference; use payloadOffset + payloadLength to read
        } else {
            parsed.payloadOffset = 0;
            parsed.payloadLength = 0;
            parsed.payloadData   = null;
        }

        return true;
    }

    // -------------------------------------------------------------------------
    // Layer parsers (private static, translated from C++ private methods)
    // -------------------------------------------------------------------------

    /**
     * Parse 14-byte Ethernet header.
     * Translated from PacketParser::parseEthernet()
     */
    private static boolean parseEthernet(byte[] data, int len,
                                         ParsedPacket parsed, int[] offset) {
        final int ETH_HEADER_LEN = 14;
        if (len < ETH_HEADER_LEN) return false;

        int pos = offset[0];

        // Destination MAC (bytes 0-5)
        parsed.destMac = macToString(data, pos);

        // Source MAC (bytes 6-11)
        parsed.srcMac = macToString(data, pos + 6);

        // EtherType (bytes 12-13, big-endian)
        parsed.etherType = readUint16BE(data, pos + 12);

        offset[0] = pos + ETH_HEADER_LEN;
        return true;
    }

    /**
     * Parse IPv4 header (20+ bytes).
     * Translated from PacketParser::parseIPv4()
     */
    private static boolean parseIPv4(byte[] data, int len,
                                     ParsedPacket parsed, int[] offset) {
        final int MIN_IP_HEADER_LEN = 20;
        int pos = offset[0];

        if (len < pos + MIN_IP_HEADER_LEN) return false;

        // First byte: version (4 bits) + IHL (4 bits)
        int versionIhl  = data[pos] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl          = versionIhl & 0x0F;  // Header length in 32-bit words

        if (parsed.ipVersion != 4) return false;

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < pos + ipHeaderLen) return false;

        parsed.ttl      = data[pos + 8] & 0xFF;
        parsed.protocol = data[pos + 9] & 0xFF;

        // Source IP (bytes 12-15), Destination IP (bytes 16-19)
        parsed.srcIp  = ipToString(data, pos + 12);
        parsed.destIp = ipToString(data, pos + 16);

        parsed.hasIp = true;
        offset[0] = pos + ipHeaderLen;
        return true;
    }

    /**
     * Parse TCP header (20+ bytes).
     * Translated from PacketParser::parseTCP()
     */
    private static boolean parseTCP(byte[] data, int len,
                                    ParsedPacket parsed, int[] offset) {
        final int MIN_TCP_HEADER_LEN = 20;
        int pos = offset[0];

        if (len < pos + MIN_TCP_HEADER_LEN) return false;

        parsed.srcPort  = readUint16BE(data, pos);
        parsed.destPort = readUint16BE(data, pos + 2);
        parsed.seqNumber = readUint32BE(data, pos + 4);
        parsed.ackNumber = readUint32BE(data, pos + 8);

        // Data offset (upper 4 bits of byte 12) — header length in 32-bit words
        int dataOffset   = (data[pos + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;

        parsed.tcpFlags = data[pos + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < pos + tcpHeaderLen) return false;

        parsed.hasTcp = true;
        offset[0] = pos + tcpHeaderLen;
        return true;
    }

    /**
     * Parse 8-byte UDP header.
     * Translated from PacketParser::parseUDP()
     */
    private static boolean parseUDP(byte[] data, int len,
                                    ParsedPacket parsed, int[] offset) {
        final int UDP_HEADER_LEN = 8;
        int pos = offset[0];

        if (len < pos + UDP_HEADER_LEN) return false;

        parsed.srcPort  = readUint16BE(data, pos);
        parsed.destPort = readUint16BE(data, pos + 2);

        parsed.hasUdp = true;
        offset[0] = pos + UDP_HEADER_LEN;
        return true;
    }

    // -------------------------------------------------------------------------
    // String conversion helpers
    // -------------------------------------------------------------------------

    /**
     * Format a MAC address as "xx:xx:xx:xx:xx:xx".
     * Translated from PacketParser::macToString()
     */
    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Format a 4-byte big-endian IP address to dotted-decimal.
     * Translated from PacketParser::ipToString()
     */
    public static String ipToString(byte[] data, int offset) {
        return (data[offset]     & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    /**
     * Convert protocol number to name string.
     * Translated from PacketParser::protocolToString()
     */
    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTO_ICMP: return "ICMP";
            case PROTO_TCP:  return "TCP";
            case PROTO_UDP:  return "UDP";
            default:         return "Unknown(" + protocol + ")";
        }
    }

    /**
     * Convert TCP flag byte to string of flag names.
     * Translated from PacketParser::tcpFlagsToString()
     */
    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");

        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }

    // -------------------------------------------------------------------------
    // Low-level binary read helpers (replaces ntohs / ntohl / reinterpret_cast)
    // -------------------------------------------------------------------------

    /** Read 2 bytes as big-endian unsigned 16-bit int (returned as int). */
    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 8) |
                (data[offset + 1] & 0xFF);
    }

    /** Read 4 bytes as big-endian unsigned 32-bit int (returned as long). */
    public static long readUint32BE(byte[] data, int offset) {
        return ((long)(data[offset]     & 0xFF) << 24) |
               ((long)(data[offset + 1] & 0xFF) << 16) |
               ((long)(data[offset + 2] & 0xFF) << 8)  |
                (long)(data[offset + 3] & 0xFF);
    }

    // -------------------------------------------------------------------------
    // Internal helper
    // -------------------------------------------------------------------------

    private static void resetParsed(ParsedPacket p) {
        p.timestampSec  = 0;
        p.timestampUsec = 0;
        p.srcMac        = null;
        p.destMac       = null;
        p.etherType     = 0;
        p.hasIp         = false;
        p.ipVersion     = 0;
        p.srcIp         = null;
        p.destIp        = null;
        p.protocol      = 0;
        p.ttl           = 0;
        p.hasTcp        = false;
        p.hasUdp        = false;
        p.srcPort       = 0;
        p.destPort      = 0;
        p.tcpFlags      = 0;
        p.seqNumber     = 0;
        p.ackNumber     = 0;
        p.payloadOffset = 0;
        p.payloadLength = 0;
        p.payloadData   = null;
    }
}
