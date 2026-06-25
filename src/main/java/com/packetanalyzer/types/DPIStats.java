package com.packetanalyzer.types;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Global DPI engine statistics counters.
 * Translated from C++ struct DPIStats in types.h
 *
 * All counters use AtomicLong (equivalent to C++ std::atomic<uint64_t>)
 * for thread-safe access without explicit locking.
 */
public class DPIStats {

    public final AtomicLong totalPackets      = new AtomicLong(0);
    public final AtomicLong totalBytes        = new AtomicLong(0);
    public final AtomicLong forwardedPackets  = new AtomicLong(0);
    public final AtomicLong droppedPackets    = new AtomicLong(0);
    public final AtomicLong tcpPackets        = new AtomicLong(0);
    public final AtomicLong udpPackets        = new AtomicLong(0);
    public final AtomicLong otherPackets      = new AtomicLong(0);
    public final AtomicLong activeConnections = new AtomicLong(0);
}
