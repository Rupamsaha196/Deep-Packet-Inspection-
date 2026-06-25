package com.packetanalyzer.types;

/**
 * Packet wrapper for passing through the processing pipeline queues.
 * Translated from C++ struct PacketJob in types.h
 *
 * Note: payload_data pointer in C++ becomes a (offset, length) pair
 * into the 'data' byte array, avoiding dangling pointer issues in Java.
 */
public class PacketJob {

    public long      packetId;
    public FiveTuple tuple;
    public byte[]    data;       // Full packet bytes (was std::vector<uint8_t>)

    // Offsets into data[]
    public int ethOffset       = 0;
    public int ipOffset        = 0;
    public int transportOffset = 0;
    public int payloadOffset   = 0;
    public int payloadLength   = 0;

    // TCP flags (uint8_t in C++)
    public int tcpFlags = 0;

    // Timestamps (uint32_t in C++ — stored as long to avoid sign issues)
    public long tsSec;
    public long tsUsec;

    /**
     * Convenience method: get a slice of data representing the payload.
     * Replaces the raw payload_data pointer from C++.
     */
    public byte[] getPayloadSlice() {
        if (payloadLength == 0 || payloadOffset >= data.length) {
            return new byte[0];
        }
        int len = Math.min(payloadLength, data.length - payloadOffset);
        byte[] slice = new byte[len];
        System.arraycopy(data, payloadOffset, slice, 0, len);
        return slice;
    }
}
