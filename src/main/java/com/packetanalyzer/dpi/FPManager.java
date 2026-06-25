package com.packetanalyzer.dpi;

import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.types.*;

import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BiConsumer;

/**
 * Manages a pool of FastPathProcessor instances.
 * Translated from C++ class FPManager in fast_path.h / fast_path.cpp
 */
public class FPManager {

    public static class AggregatedStats {
        public long totalProcessed;
        public long totalForwarded;
        public long totalDropped;
        public long totalConnections;
    }

    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager,
                     BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) fp.start();
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) fp.stop();
    }

    public FastPathProcessor getFP(int index) { return fps.get(index); }

    /** Return input queues of all FPs (used by LBManager). */
    public List<LinkedBlockingQueue<PacketJob>> getQueuePtrs() {
        List<LinkedBlockingQueue<PacketJob>> queues = new ArrayList<>();
        for (FastPathProcessor fp : fps) queues.add(fp.getInputQueue());
        return queues;
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats s = fp.getStats();
            stats.totalProcessed   += s.packetsProcessed;
            stats.totalForwarded   += s.packetsForwarded;
            stats.totalDropped     += s.packetsDropped;
            stats.totalConnections += s.connectionsTracked;
        }
        return stats;
    }

    /** Generate a per-application classification report across all FPs. */
    public String generateClassificationReport() {
        Map<AppType, Long> appCounts    = new EnumMap<>(AppType.class);
        Map<String, Long>  domainCounts = new HashMap<>();
        long totalClassified = 0;
        long totalUnknown    = 0;

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
                if (conn.appType == AppType.UNKNOWN) {
                    // counted below via totalUnknown
                } else {
                    // counted below via totalClassified
                }
                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.merge(conn.sni, 1L, Long::sum);
                }
            });
        }

        for (Map.Entry<AppType, Long> e : appCounts.entrySet()) {
            if (e.getKey() == AppType.UNKNOWN) totalUnknown    += e.getValue();
            else                               totalClassified += e.getValue();
        }

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
        double unknownPct    = total > 0 ? (100.0 * totalUnknown    / total) : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Total Connections:    %10d                           ║%n", total));
        sb.append(String.format("║ Classified:           %10d (%.1f%%)                  ║%n",
                                totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%.1f%%)                  ║%n",
                                totalUnknown, unknownPct));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        appCounts.entrySet().stream()
                 .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                 .forEach(e -> {
                     double pct = total > 0 ? (100.0 * e.getValue() / total) : 0;
                     int barLen = (int)(pct / 5);
                     String bar = "#".repeat(barLen);
                     sb.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                                             e.getKey().toDisplayString(),
                                             e.getValue(), pct, bar));
                 });

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }
}
