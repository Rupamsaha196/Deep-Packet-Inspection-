package com.packetanalyzer.dpi;

import com.packetanalyzer.types.*;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Global view across all FP ConnectionTrackers — for reporting only.
 * Translated from C++ class GlobalConnectionTable in connection_tracker.h / connection_tracker.cpp
 */
public class GlobalConnectionTable {

    // -------------------------------------------------------------------------
    // Inner stats class
    // -------------------------------------------------------------------------
    public static class GlobalStats {
        public long totalActiveConnections;
        public long totalConnectionsSeen;
        public Map<AppType, Long>                     appDistribution = new EnumMap<>(AppType.class);
        public List<Map.Entry<String, Long>>          topDomains      = new ArrayList<>();
    }

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------
    private final List<ConnectionTracker> trackers;
    private final ReadWriteLock mutex = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        trackers = new ArrayList<>(Collections.nCopies(numFps, null));
    }

    /** Register a tracker for a given FP id. */
    public void registerTracker(int fpId, ConnectionTracker tracker) {
        mutex.writeLock().lock();
        try {
            if (fpId < trackers.size()) trackers.set(fpId, tracker);
        } finally {
            mutex.writeLock().unlock();
        }
    }

    /** Aggregate stats from all registered FP trackers. */
    public GlobalStats getGlobalStats() {
        mutex.readLock().lock();
        try {
            GlobalStats stats = new GlobalStats();
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats ts = tracker.getStats();
                stats.totalActiveConnections += ts.activeConnections;
                stats.totalConnectionsSeen   += ts.totalConnectionsSeen;

                tracker.forEach(conn -> {
                    stats.appDistribution.merge(conn.appType, 1L, Long::sum);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            // Top 20 domains by connection count
            List<Map.Entry<String, Long>> domainList = new ArrayList<>(domainCounts.entrySet());
            domainList.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            int count = Math.min(domainList.size(), 20);
            stats.topDomains = domainList.subList(0, count);

            return stats;
        } finally {
            mutex.readLock().unlock();
        }
    }

    /** Generate a formatted report of global connection statistics. */
    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Active Connections:     %10d                          ║%n",
                                stats.totalActiveConnections));
        sb.append(String.format("║ Total Connections Seen: %10d                          ║%n",
                                stats.totalConnectionsSeen));

        if (!stats.appDistribution.isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                    APPLICATION BREAKDOWN                      ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");

            long total = stats.appDistribution.values().stream().mapToLong(Long::longValue).sum();
            stats.appDistribution.entrySet().stream()
                 .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                 .forEach(e -> {
                     double pct = total > 0 ? (100.0 * e.getValue() / total) : 0;
                     sb.append(String.format("║ %-20s %10d (%5.1f%%)           ║%n",
                                             e.getKey().toDisplayString(), e.getValue(), pct));
                 });
        }

        if (!stats.topDomains.isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                      TOP DOMAINS                             ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            for (Map.Entry<String, Long> e : stats.topDomains) {
                String domain = e.getKey();
                if (domain.length() > 35) domain = domain.substring(0, 32) + "...";
                sb.append(String.format("║ %-40s %10d           ║%n", domain, e.getValue()));
            }
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }
}
