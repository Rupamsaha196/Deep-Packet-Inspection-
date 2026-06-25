package com.packetanalyzer.pcap;

import java.io.*;

/**
 * Reads .pcap files and yields raw packets one at a time.
 * Translated from C++ class PcapReader in pcap_reader.h / pcap_reader.cpp
 *
 * Key translation notes:
 *  - std::ifstream -> DataInputStream wrapping BufferedInputStream
 *  - reinterpret_cast<char*>(&struct) -> manual byte-by-byte reading
 *  - Byte-swap logic mirrors the C++ maybeSwap16/maybeSwap32 methods
 */
public class PcapReader implements AutoCloseable {

    // Magic numbers (from pcap_reader.cpp)
    private static final long PCAP_MAGIC_NATIVE  = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private DataInputStream stream;
    private PcapGlobalHeader globalHeader;
    private boolean needsByteSwap = false;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Open a .pcap file for reading and validate / parse the global header.
     * Translated from PcapReader::open() in pcap_reader.cpp
     *
     * @param filename path to the .pcap file
     * @return true on success, false on error
     */
    public boolean open(String filename) {
        close();
        try {
            stream = new DataInputStream(new BufferedInputStream(new FileInputStream(filename)));
        } catch (FileNotFoundException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }

        globalHeader = new PcapGlobalHeader();
        try {
            // Read 24-byte global header
            long magic = readUint32Raw();
            if (magic == PCAP_MAGIC_NATIVE) {
                needsByteSwap = false;
            } else if (magic == PCAP_MAGIC_SWAPPED) {
                needsByteSwap = true;
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magic);
                close();
                return false;
            }
            globalHeader.magicNumber  = magic;
            globalHeader.versionMajor = (int) maybeSwap16(readUint16Raw());
            globalHeader.versionMinor = (int) maybeSwap16(readUint16Raw());
            globalHeader.thisZone     = (int) maybeSwap32(readUint32Raw());
            globalHeader.sigFigs      = maybeSwap32(readUint32Raw());
            globalHeader.snapLen      = maybeSwap32(readUint32Raw());
            globalHeader.network      = maybeSwap32(readUint32Raw());
        } catch (IOException e) {
            System.err.println("Error: Could not read PCAP global header");
            close();
            return false;
        }

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
        System.out.println("  Snaplen: " + globalHeader.snapLen + " bytes");
        System.out.println("  Link type: " + globalHeader.network +
                           (globalHeader.network == 1 ? " (Ethernet)" : ""));
        return true;
    }

    /**
     * Read the next packet from the file into {@code packet}.
     * Returns false at EOF or on read error.
     * Translated from PcapReader::readNextPacket() in pcap_reader.cpp
     */
    public boolean readNextPacket(RawPacket packet) {
        if (stream == null) return false;
        try {
            // Read 16-byte packet header
            packet.header.tsSec   = maybeSwap32(readUint32Raw());
            packet.header.tsUsec  = maybeSwap32(readUint32Raw());
            packet.header.inclLen = maybeSwap32(readUint32Raw());
            packet.header.origLen = maybeSwap32(readUint32Raw());
        } catch (EOFException e) {
            return false; // Normal end of file
        } catch (IOException e) {
            return false;
        }

        // Sanity check on packet length
        if (packet.header.inclLen > globalHeader.snapLen || packet.header.inclLen > 65535) {
            System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
            return false;
        }

        // Read packet data
        packet.data = new byte[(int) packet.header.inclLen];
        try {
            int bytesRead = 0;
            while (bytesRead < packet.data.length) {
                int n = stream.read(packet.data, bytesRead, packet.data.length - bytesRead);
                if (n < 0) {
                    System.err.println("Error: Could not read packet data");
                    return false;
                }
                bytesRead += n;
            }
        } catch (IOException e) {
            System.err.println("Error: Could not read packet data");
            return false;
        }

        return true;
    }

    /** Close the underlying file stream. */
    @Override
    public void close() {
        if (stream != null) {
            try { stream.close(); } catch (IOException ignored) {}
            stream = null;
        }
        needsByteSwap = false;
    }

    public PcapGlobalHeader getGlobalHeader() { return globalHeader; }
    public boolean isOpen()                   { return stream != null; }
    public boolean needsByteSwap()            { return needsByteSwap; }

    // -------------------------------------------------------------------------
    // Write helpers (used by DPIEngine to write output PCAP)
    // -------------------------------------------------------------------------

    /**
     * Serialize the global header to bytes (for writing output PCAP files).
     * Mirrors the layout expected by Wireshark / other tools.
     */
    public static byte[] globalHeaderToBytes(PcapGlobalHeader h) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(24);
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt((int) h.magicNumber);
        dos.writeShort((short) h.versionMajor);
        dos.writeShort((short) h.versionMinor);
        dos.writeInt(h.thisZone);
        dos.writeInt((int) h.sigFigs);
        dos.writeInt((int) h.snapLen);
        dos.writeInt((int) h.network);
        return baos.toByteArray();
    }

    /**
     * Serialize a packet header to bytes (for writing output PCAP files).
     */
    public static byte[] packetHeaderToBytes(PcapPacketHeader h) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(16);
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt((int) h.tsSec);
        dos.writeInt((int) h.tsUsec);
        dos.writeInt((int) h.inclLen);
        dos.writeInt((int) h.origLen);
        return baos.toByteArray();
    }

    // -------------------------------------------------------------------------
    // Private helpers — byte order
    // -------------------------------------------------------------------------

    /** Read 2 raw bytes as big-endian unsigned short (no swap yet). */
    private long readUint16Raw() throws IOException {
        int b0 = stream.read();
        int b1 = stream.read();
        if (b0 < 0 || b1 < 0) throw new EOFException();
        return ((b0 & 0xFF) << 8) | (b1 & 0xFF);
    }

    /** Read 4 raw bytes as big-endian unsigned int (no swap yet). */
    private long readUint32Raw() throws IOException {
        int b0 = stream.read();
        int b1 = stream.read();
        int b2 = stream.read();
        int b3 = stream.read();
        if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) throw new EOFException();
        return ((long)(b0 & 0xFF) << 24) | ((long)(b1 & 0xFF) << 16) |
               ((long)(b2 & 0xFF) << 8)  |  (long)(b3 & 0xFF);
    }

    /**
     * Swap bytes of a uint16 if the file uses non-native byte order.
     * Translated from PcapReader::maybeSwap16()
     */
    private long maybeSwap16(long value) {
        if (!needsByteSwap) return value;
        return ((value & 0xFF00L) >> 8) | ((value & 0x00FFL) << 8);
    }

    /**
     * Swap bytes of a uint32 if the file uses non-native byte order.
     * Translated from PcapReader::maybeSwap32()
     */
    private long maybeSwap32(long value) {
        if (!needsByteSwap) return value;
        return ((value & 0xFF000000L) >> 24) |
               ((value & 0x00FF0000L) >> 8)  |
               ((value & 0x0000FF00L) << 8)  |
               ((value & 0x000000FFL) << 24);
    }
}
