package com.packetanalyzer.types;

import java.util.Objects;

/**
 * Five-tuple that uniquely identifies a network connection/flow.
 * Translated from C++ struct FiveTuple in types.h / types.cpp
 *
 * Note: Java has no unsigned integer types.
 *   - src_ip / dst_ip are stored as long (treating uint32 bit-pattern)
 *   - src_port / dst_port are stored as int (treating uint16 bit-pattern)
 *   - protocol is stored as int (treating uint8 bit-pattern)
 * Use & 0xFFFFFFFFL, & 0xFFFF, & 0xFF when doing arithmetic comparisons.
 */
public class FiveTuple {

    public final long srcIp;    // uint32_t — network byte order preserved
    public final long dstIp;    // uint32_t
    public final int  srcPort;  // uint16_t
    public final int  dstPort;  // uint16_t
    public final int  protocol; // uint8_t  — 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /**
     * Create the reverse tuple (for bidirectional flow matching).
     * Translated from FiveTuple::reverse() in types.h
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /**
     * Human-readable representation of the five-tuple.
     * Translated from FiveTuple::toString() in types.cpp
     */
    @Override
    public String toString() {
        return formatIp(srcIp) + ":" + (srcPort & 0xFFFF) +
               " -> " +
               formatIp(dstIp) + ":" + (dstPort & 0xFFFF) +
               " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
    }

    /** Format a uint32 IP (stored as long) to dotted-decimal string. */
    public static String formatIp(long ip) {
        return ((ip) & 0xFF) + "." +
               ((ip >> 8)  & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    /**
     * Hash function matching the C++ FiveTupleHash.
     * Uses the same boost::hash_combine-style mixing.
     */
    @Override
    public int hashCode() {
        long h = 0;
        h ^= Long.hashCode(srcIp)  + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Long.hashCode(dstIp)  + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(srcPort)  + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstPort)  + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >> 2);
        return (int) h;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple that = (FiveTuple) o;
        return srcIp == that.srcIp &&
               dstIp == that.dstIp &&
               srcPort == that.srcPort &&
               dstPort == that.dstPort &&
               protocol == that.protocol;
    }
}
