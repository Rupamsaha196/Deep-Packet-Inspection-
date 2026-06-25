package com.packetanalyzer.dpi;

import com.packetanalyzer.extractor.DNSExtractor;
import com.packetanalyzer.extractor.HTTPHostExtractor;
import com.packetanalyzer.extractor.SNIExtractor;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.types.*;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Processes packets on a single "fast path" thread:
 * - Maintains a per-FP connection table
 * - Classifies traffic via SNI / HTTP Host / DNS / port heuristics
 * - Applies blocking rules
 * Translated from C++ class FastPathProcessor in fast_path.h / fast_path.cpp
 */
public class FastPathProcessor {

    // -------------------------------------------------------------------------
    // Inner stats class (was FastPathProcessor::FPStats in fast_path.h)
    // -------------------------------------------------------------------------
    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
        public long sniExtractions;
        public long classificationHits;
    }

    // -------------------------------------------------------------------------
    // TCP flags constants (was local constexpr in fast_path.cpp)
    // -------------------------------------------------------------------------
    private static final int TCP_SYN = 0x02;
    private static final int TCP_ACK = 0x10;
    private static final int TCP_FIN = 0x01;
    private static final int TCP_RST = 0x04;

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------
    private final int                        fpId;
    private final LinkedBlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker          connTracker;
    private final RuleManager                ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private volatile boolean running = false;
    private Thread           thread;

    // Atomic counters (std::atomic<uint64_t> equivalents)
    private final AtomicLong packetsProcessed   = new AtomicLong(0);
    private final AtomicLong packetsForwarded   = new AtomicLong(0);
    private final AtomicLong packetsDropped     = new AtomicLong(0);
    private final AtomicLong sniExtractions     = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public FastPathProcessor(int fpId, RuleManager ruleManager,
                             BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId           = fpId;
        this.inputQueue     = new LinkedBlockingQueue<>(10_000);
        this.connTracker    = new ConnectionTracker(fpId);
        this.ruleManager    = ruleManager;
        this.outputCallback = outputCallback;
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /** Start the FP processing thread. Translated from FastPathProcessor::start() */
    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "FP-" + fpId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    /** Stop the FP thread gracefully. Translated from FastPathProcessor::stop() */
    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.offer(new PacketJob()); // wake up the blocked poll
        if (thread != null) {
            try { thread.join(2000); } catch (InterruptedException ignored) {}
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    /** Main processing loop. Translated from FastPathProcessor::run() */
    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null || job.tuple == null) {
                    // Timeout or poison pill — periodic cleanup
                    connTracker.cleanupStale(300);
                    continue;
                }

                packetsProcessed.incrementAndGet();

                PacketAction action = processPacket(job);

                if (outputCallback != null) {
                    outputCallback.accept(job, action);
                }

                if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                } else {
                    packetsForwarded.incrementAndGet();
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Packet processing pipeline
    // -------------------------------------------------------------------------

    /**
     * Process a single packet: classify, check rules, return action.
     * Translated from FastPathProcessor::processPacket()
     */
    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) return PacketAction.FORWARD;

        // Update connection stats
        connTracker.updateConnection(conn, job.data.length, true);

        // TCP state machine update
        if (job.tuple.protocol == 6) {
            updateTCPState(conn, job.tcpFlags);
        }

        // Already blocked — drop immediately
        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        // Payload inspection for unclassified connections
        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    /**
     * Try to classify the connection by inspecting the payload.
     * Translated from FastPathProcessor::inspectPayload()
     */
    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) return;

        // 1. TLS SNI
        if (tryExtractSNI(job, conn)) return;

        // 2. HTTP Host
        if (tryExtractHTTPHost(job, conn)) return;

        // 3. DNS (port 53)
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            byte[] payload = Arrays.copyOfRange(job.data, job.payloadOffset,
                                                job.payloadOffset + job.payloadLength);
            Optional<String> domain = DNSExtractor.extractQuery(payload, payload.length);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // 4. Port-based fallback
        if (job.tuple.dstPort == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    /** Try TLS SNI extraction. Translated from FastPathProcessor::tryExtractSNI() */
    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

        byte[] payload = Arrays.copyOfRange(job.data, job.payloadOffset,
                                            job.payloadOffset + job.payloadLength);
        Optional<String> sni = SNIExtractor.extract(payload, payload.length);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();
            AppType app = AppType.fromSni(sni.get());
            connTracker.classifyConnection(conn, app, sni.get());
            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    /** Try HTTP Host extraction. Translated from FastPathProcessor::tryExtractHTTPHost() */
    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80) return false;
        if (job.payloadOffset >= job.data.length || job.payloadLength == 0) return false;

        byte[] payload = Arrays.copyOfRange(job.data, job.payloadOffset,
                                            job.payloadOffset + job.payloadLength);
        Optional<String> host = HTTPHostExtractor.extract(payload, payload.length);
        if (host.isPresent()) {
            AppType app = AppType.fromSni(host.get());
            connTracker.classifyConnection(conn, app, host.get());
            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    /**
     * Evaluate all blocking rules. Translated from FastPathProcessor::checkRules()
     */
    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;

        Optional<RuleManager.BlockReason> reason = ruleManager.shouldBlock(
            job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);

        if (reason.isPresent()) {
            RuleManager.BlockReason r = reason.get();
            String detail = switch (r.type) {
                case IP     -> "IP "     + r.detail;
                case APP    -> "App "    + r.detail;
                case DOMAIN -> "Domain " + r.detail;
                case PORT   -> "Port "   + r.detail;
            };
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + detail);
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    /**
     * Update TCP state machine flags on the connection.
     * Translated from FastPathProcessor::updateTCPState()
     */
    private void updateTCPState(Connection conn, int flags) {
        if ((flags & TCP_SYN) != 0) {
            if ((flags & TCP_ACK) != 0) conn.synAckSeen = true;
            else                         conn.synSeen    = true;
        }
        if (conn.synSeen && conn.synAckSeen && (flags & TCP_ACK) != 0) {
            if (conn.state == ConnectionState.NEW) conn.state = ConnectionState.ESTABLISHED;
        }
        if ((flags & TCP_FIN) != 0) conn.finSeen = true;
        if ((flags & TCP_RST) != 0) conn.state = ConnectionState.CLOSED;
        if (conn.finSeen && (flags & TCP_ACK) != 0) conn.state = ConnectionState.CLOSED;
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    public LinkedBlockingQueue<PacketJob> getInputQueue()       { return inputQueue; }
    public ConnectionTracker             getConnectionTracker() { return connTracker; }

    public FPStats getStats() {
        FPStats s = new FPStats();
        s.packetsProcessed   = packetsProcessed.get();
        s.packetsForwarded   = packetsForwarded.get();
        s.packetsDropped     = packetsDropped.get();
        s.connectionsTracked = connTracker.getActiveCount();
        s.sniExtractions     = sniExtractions.get();
        s.classificationHits = classificationHits.get();
        return s;
    }
}
