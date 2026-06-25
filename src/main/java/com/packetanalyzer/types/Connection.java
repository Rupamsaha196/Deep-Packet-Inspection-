package com.packetanalyzer.types;

import java.time.Instant;

/**
 * Represents a tracked network connection/flow.
 * Translated from C++ struct Connection in types.h
 */
public class Connection {

    public FiveTuple       tuple;
    public ConnectionState state   = ConnectionState.NEW;
    public AppType         appType = AppType.UNKNOWN;
    public String          sni     = "";   // Server Name Indication (if detected)

    public long packetsIn  = 0;
    public long packetsOut = 0;
    public long bytesIn    = 0;
    public long bytesOut   = 0;

    // Translated from std::chrono::steady_clock::time_point
    public Instant firstSeen;
    public Instant lastSeen;

    public PacketAction action = PacketAction.FORWARD;

    // TCP state tracking fields
    public boolean synSeen    = false;
    public boolean synAckSeen = false;
    public boolean finSeen    = false;

    public Connection() {
        firstSeen = Instant.now();
        lastSeen  = firstSeen;
    }
}
