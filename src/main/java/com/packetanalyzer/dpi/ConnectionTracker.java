package com.packetanalyzer.dpi;

import com.packetanalyzer.types.*;

import java.time.Instant;
import java.util.*;

/**
 * Tracks active network connections for a single Fast Path thread.
 * Translated from C++ class ConnectionTracker in connection_tracker.h / connection_tracker.cpp
 *
 * Note: No locking needed — each ConnectionTracker is owned by exactly one FP thread.
 */
public class ConnectionTracker {

    // -------------------------------------------------------------------------
    // Inner stats class
    // -------------------------------------------------------------------------
    public static class TrackerStats {
        public long activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------
    private final int                          fpId;
    private final int                          maxConnections;
    private final Map<FiveTuple, Connection>   connections = new LinkedHashMap<>();

    private long totalSeen        = 0;
    private long classifiedCount  = 0;
    private long blockedCount     = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId           = fpId;
        this.maxConnections = maxConnections;
    }

    // -------------------------------------------------------------------------
    // Core operations
    // -------------------------------------------------------------------------

    /**
     * Get an existing connection or create a new one.
     * Translated from ConnectionTracker::getOrCreateConnection()
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection();
        conn.tuple     = tuple;
        conn.state     = ConnectionState.NEW;
        conn.firstSeen = Instant.now();
        conn.lastSeen  = conn.firstSeen;

        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    /**
     * Look up a connection, also trying the reverse tuple.
     * Translated from ConnectionTracker::getConnection()
     */
    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        return connections.get(tuple.reverse());
    }

    /**
     * Update per-connection byte/packet counters and last-seen timestamp.
     * Translated from ConnectionTracker::updateConnection()
     */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    /**
     * Mark a connection as classified with an application type and SNI.
     * Translated from ConnectionTracker::classifyConnection()
     */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni     = sni != null ? sni : "";
            conn.state   = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    /**
     * Mark a connection as blocked.
     * Translated from ConnectionTracker::blockConnection()
     */
    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state  = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) conn.state = ConnectionState.CLOSED;
    }

    /**
     * Remove stale connections (not seen within timeoutSeconds).
     * Translated from ConnectionTracker::cleanupStale()
     */
    public long cleanupStale(long timeoutSeconds) {
        Instant cutoff = Instant.now().minusSeconds(timeoutSeconds);
        long removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            Connection conn = entry.getValue();
            if (conn.lastSeen.isBefore(cutoff) || conn.state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public long getActiveCount() { return connections.size(); }

    public TrackerStats getStats() {
        TrackerStats s = new TrackerStats();
        s.activeConnections      = connections.size();
        s.totalConnectionsSeen   = totalSeen;
        s.classifiedConnections  = classifiedCount;
        s.blockedConnections     = blockedCount;
        return s;
    }

    public void clear() { connections.clear(); }

    /** Iterate all connections — used for reporting. */
    public void forEach(java.util.function.Consumer<Connection> action) {
        for (Connection conn : connections.values()) {
            action.accept(conn);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Evict the connection with the oldest last-seen timestamp. */
    private void evictOldest() {
        if (connections.isEmpty()) return;
        FiveTuple oldest = null;
        Instant   oldestTime = Instant.MAX;
        for (Map.Entry<FiveTuple, Connection> e : connections.entrySet()) {
            if (e.getValue().lastSeen.isBefore(oldestTime)) {
                oldestTime = e.getValue().lastSeen;
                oldest     = e.getKey();
            }
        }
        if (oldest != null) connections.remove(oldest);
    }
}
