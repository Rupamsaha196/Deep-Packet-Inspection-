package com.packetanalyzer;

import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.pcap.PcapReader;
import com.packetanalyzer.pcap.RawPacket;

import java.time.*;
import java.time.format.DateTimeFormatter;

/**
 * Basic PCAP reader and packet display.
 * Translated from C++ main.cpp
 *
 * Usage:
 * mvn exec:java -Dexec.args="capture.pcap [max_packets]"
 * java -jar packet-analyzer.jar capture.pcap [max_packets]
 */
public class Main {

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0          ");
        System.out.println("====================================\n");

        String filename = "test_dpi.pcap";
        int maxPackets = -1;

        if (args.length >= 1) {
            filename = args[0];
        } else {
            System.out.println("No arguments provided. Using default: test_dpi.pcap");
        }

        if (args.length >= 2) {
            maxPackets = Integer.parseInt(args[1]);
        }

        // Open the PCAP file
        PcapReader reader = new PcapReader();
        if (!reader.open(filename)) {
            System.exit(1);
        }

        System.out.println("\n--- Reading packets ---");

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        int packetCount = 0;
        int parseErrors = 0;

        while (reader.readNextPacket(raw)) {
            packetCount++;

            if (PacketParser.parse(raw, parsed)) {
                printPacketSummary(parsed, packetCount);
            } else {
                System.err.println("Warning: Failed to parse packet #" + packetCount);
                parseErrors++;
            }

            if (maxPackets > 0 && packetCount >= maxPackets) {
                System.out.println("\n(Stopped after " + maxPackets + " packets)");
                break;
            }
        }

        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + packetCount);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");

        reader.close();
    }

    /**
     * Print a human-readable summary of one parsed packet.
     * Translated from printPacketSummary() in main.cpp
     */
    private static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        // Format timestamp
        Instant instant = Instant.ofEpochSecond(pkt.timestampSec, pkt.timestampUsec * 1000L);
        LocalDateTime ldt = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());

        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.printf("Time: %s.%06d%n", ldt.format(TS_FMT), pkt.timestampUsec);

        // Ethernet layer
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        String etherDesc = switch (pkt.etherType) {
            case PacketParser.ETHER_IPv4 -> " (IPv4)";
            case PacketParser.ETHER_IPv6 -> " (IPv6)";
            case PacketParser.ETHER_ARP -> " (ARP)";
            default -> "";
        };
        System.out.printf("  EtherType:       0x%04X%s%n", pkt.etherType, etherDesc);

        // IP layer
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // TCP layer
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + (pkt.srcPort & 0xFFFF));
            System.out.println("  Destination Port: " + (pkt.destPort & 0xFFFF));
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // UDP layer
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + (pkt.srcPort & 0xFFFF));
            System.out.println("  Destination Port: " + (pkt.destPort & 0xFFFF));
        }

        // Payload
        if (pkt.payloadLength > 0 && pkt.payloadData != null) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");

            // Print first 32 bytes as hex
            int previewLen = Math.min(pkt.payloadLength, 32);
            StringBuilder hex = new StringBuilder("  Preview: ");
            for (int i = 0; i < previewLen; i++) {
                hex.append(String.format("%02x ", pkt.payloadData[pkt.payloadOffset + i] & 0xFF));
            }
            if (pkt.payloadLength > 32)
                hex.append("...");
            System.out.println(hex);
        }
    }

    private static void printUsage(String programName) {
        System.out.println("Usage: " + programName + " <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  " + programName + " capture.pcap");
        System.out.println("  " + programName + " capture.pcap 10");
    }
}
