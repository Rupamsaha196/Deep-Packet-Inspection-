package com.packetanalyzer.dpi;

import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.pcap.*;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.types.*;

import java.io.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Top-level DPI engine orchestrator.
 * Translated from C++ class DPIEngine in dpi_engine.h / dpi_engine.cpp
 *
 * Architecture:
 *   Reader thread → LB threads → FP threads → Output thread
 *
 * Translation notes:
 *   - std::thread        → Thread
 *   - std::ofstream      → FileOutputStream / DataOutputStream
 *   - std::unique_ptr    → plain reference (GC handles memory)
 *   - std::atomic<bool>  → volatile boolean / AtomicBoolean
 */
public class DPIEngine {

    // -------------------------------------------------------------------------
    // Configuration (was DPIEngine::Config in dpi_engine.h)
    // -------------------------------------------------------------------------
    public static class Config {
        public int    numLoadBalancers = 2;
        public int    fpsPerLb        = 2;
        public String rulesFile       = "";
    }

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------
    private final Config     config;
    private RuleManager      ruleManager;
    private FPManager        fpManager;
    private LBManager        lbManager;
    private GlobalConnectionTable globalConnTable;

    private final DPIStats   stats    = new DPIStats();
    private volatile boolean running  = false;
    private AtomicBoolean    processingComplete = new AtomicBoolean(false);

    private Thread readerThread;
    private Thread outputThread;

    private final LinkedBlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10_000);

    private OutputStream outputFileStream;
    private final Object outputMutex = new Object();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public DPIEngine(Config config) {
        this.config = config;
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                                ║");
        System.out.printf ("║   Load Balancers:    %3d                                       ║%n", config.numLoadBalancers);
        System.out.printf ("║   FPs per LB:        %3d                                       ║%n", config.fpsPerLb);
        System.out.printf ("║   Total FP threads:  %3d                                       ║%n", config.numLoadBalancers * config.fpsPerLb);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /** Initialize all sub-components. Translated from DPIEngine::initialize() */
    public boolean initialize() {
        ruleManager = new RuleManager();
        if (!config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;

        fpManager = new FPManager(totalFps, ruleManager, this::handleOutput);
        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb,
                                  fpManager.getQueuePtrs());

        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    /** Start all processing threads. Translated from DPIEngine::start() */
    public void start() {
        if (running) return;
        running = true;
        processingComplete.set(false);

        outputThread = new Thread(this::outputThreadFunc, "OutputThread");
        outputThread.setDaemon(true);
        outputThread.start();

        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    /** Stop all threads gracefully. Translated from DPIEngine::stop() */
    public void stop() {
        if (!running) return;
        running = false;

        lbManager.stopAll();
        fpManager.stopAll();

        // Drain the output queue
        outputQueue.offer(new PacketJob()); // wake up output thread
        if (outputThread != null) {
            try { outputThread.join(3000); } catch (InterruptedException ignored) {}
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    /** Wait for the reader to finish. Translated from DPIEngine::waitForCompletion() */
    public void waitForCompletion() {
        if (readerThread != null) {
            try { readerThread.join(); } catch (InterruptedException ignored) {}
        }
        // Allow queues to drain
        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        processingComplete.set(true);
    }

    // -------------------------------------------------------------------------
    // Main processing entry point
    // -------------------------------------------------------------------------

    /**
     * Process a PCAP file and write filtered output to another PCAP file.
     * Translated from DPIEngine::processFile()
     */
    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        if (ruleManager == null && !initialize()) return false;

        // Open output file
        try {
            outputFileStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        start();

        readerThread = new Thread(() -> readerThreadFunc(inputFile), "ReaderThread");
        readerThread.setDaemon(true);
        readerThread.start();

        waitForCompletion();

        try { Thread.sleep(200); } catch (InterruptedException ignored) {}

        stop();

        synchronized (outputMutex) {
            if (outputFileStream != null) {
                try { outputFileStream.close(); } catch (IOException ignored) {}
                outputFileStream = null;
            }
        }

        System.out.print(generateReport());
        System.out.print(fpManager.generateClassificationReport());

        return true;
    }

    // -------------------------------------------------------------------------
    // Reader thread
    // -------------------------------------------------------------------------

    /**
     * Read a PCAP file and send packets into the LB pipeline.
     * Translated from DPIEngine::readerThreadFunc()
     */
    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        // Write PCAP global header to output
        try {
            byte[] headerBytes = PcapReader.globalHeaderToBytes(reader.getGlobalHeader());
            synchronized (outputMutex) {
                if (outputFileStream != null) outputFileStream.write(headerBytes);
            }
        } catch (IOException e) {
            System.err.println("[Reader] Error writing output header");
        }

        RawPacket    raw    = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        long         packetId = 0;

        System.out.println("[Reader] Starting packet processing...");

        while (reader.readNextPacket(raw)) {
            if (!PacketParser.parse(raw, parsed)) continue;

            // Only process IP + TCP/UDP packets
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            PacketJob job = createPacketJob(raw, parsed, packetId++);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);
            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else                stats.udpPackets.incrementAndGet();

            // Send to the correct LB
            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
            try {
                lb.getInputQueue().put(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    // -------------------------------------------------------------------------
    // Output thread
    // -------------------------------------------------------------------------

    /** Write forwarded packets to the output PCAP file. Translated from DPIEngine::outputThreadFunc() */
    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null && job.tuple != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /** Called by FP threads for each processed packet. Translated from DPIEngine::handleOutput() */
    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.offer(job);
    }

    /** Write a single forwarded packet to the output PCAP. */
    private void writeOutputPacket(PacketJob job) {
        synchronized (outputMutex) {
            if (outputFileStream == null) return;
            try {
                PcapPacketHeader hdr = new PcapPacketHeader();
                hdr.tsSec   = job.tsSec;
                hdr.tsUsec  = job.tsUsec;
                hdr.inclLen = job.data.length;
                hdr.origLen = job.data.length;
                outputFileStream.write(PcapReader.packetHeaderToBytes(hdr));
                outputFileStream.write(job.data);
            } catch (IOException ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // PacketJob factory
    // -------------------------------------------------------------------------

    /**
     * Build a PacketJob from a raw + parsed packet pair.
     * Translated from DPIEngine::createPacketJob()
     */
    private static PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, long packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec    = raw.header.tsSec;
        job.tsUsec   = raw.header.tsUsec;

        // Parse IP addresses from dotted-decimal strings back to uint32 (stored as long)
        job.tuple = new FiveTuple(
            parseIPString(parsed.srcIp),
            parseIPString(parsed.destIp),
            parsed.srcPort,
            parsed.destPort,
            parsed.protocol
        );

        job.tcpFlags = parsed.tcpFlags;
        job.data     = raw.data.clone();

        // Calculate offsets
        job.ethOffset = 0;
        job.ipOffset  = 14; // Ethernet header = 14 bytes

        if (job.data.length > 14) {
            int ipIhl         = job.data[14] & 0x0F;
            int ipHeaderLen   = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;

            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >> 4) & 0x0F;
                job.payloadOffset = job.transportOffset + tcpDataOffset * 4;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }

            if (job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    /** Parse a dotted-decimal IP string into a uint32 stored as long. */
    private static long parseIPString(String ip) {
        if (ip == null) return 0;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i]) << (i * 8));
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Rule management API (pass-through to RuleManager)
    // -------------------------------------------------------------------------

    public void blockIP(String ip)            { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void unblockIP(String ip)          { if (ruleManager != null) ruleManager.unblockIP(ip); }
    public void blockApp(AppType app)         { if (ruleManager != null) ruleManager.blockApp(app); }
    public void unblockApp(AppType app)       { if (ruleManager != null) ruleManager.unblockApp(app); }
    public void blockDomain(String domain)    { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain)  { if (ruleManager != null) ruleManager.unblockDomain(domain); }
    public boolean loadRules(String filename) { return ruleManager != null && ruleManager.loadRules(filename); }
    public boolean saveRules(String filename) { return ruleManager != null && ruleManager.saveRules(filename); }

    // -------------------------------------------------------------------------
    // Reporting
    // -------------------------------------------------------------------------

    /** Generate the engine statistics report. Translated from DPIEngine::generateReport() */
    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                    DPI ENGINE STATISTICS                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║ PACKET STATISTICS                                             ║\n");
        sb.append(String.format("║   Total Packets:      %12d                        ║%n", stats.totalPackets.get()));
        sb.append(String.format("║   Total Bytes:        %12d                        ║%n", stats.totalBytes.get()));
        sb.append(String.format("║   TCP Packets:        %12d                        ║%n", stats.tcpPackets.get()));
        sb.append(String.format("║   UDP Packets:        %12d                        ║%n", stats.udpPackets.get()));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║ FILTERING STATISTICS                                          ║\n");
        sb.append(String.format("║   Forwarded:          %12d                        ║%n", stats.forwardedPackets.get()));
        sb.append(String.format("║   Dropped/Blocked:    %12d                        ║%n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            sb.append(String.format("║   Drop Rate:          %11.2f%%                        ║%n", dropRate));
        }

        if (lbManager != null) {
            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            sb.append(String.format("║   LB Received:        %12d                        ║%n", lbStats.totalReceived));
            sb.append(String.format("║   LB Dispatched:      %12d                        ║%n", lbStats.totalDispatched));
        }

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ FAST PATH STATISTICS                                          ║\n");
            sb.append(String.format("║   FP Processed:       %12d                        ║%n", fpStats.totalProcessed));
            sb.append(String.format("║   FP Forwarded:       %12d                        ║%n", fpStats.totalForwarded));
            sb.append(String.format("║   FP Dropped:         %12d                        ║%n", fpStats.totalDropped));
            sb.append(String.format("║   Active Connections: %12d                        ║%n", fpStats.totalConnections));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats rs = ruleManager.getStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ BLOCKING RULES                                                ║\n");
            sb.append(String.format("║   Blocked IPs:        %12d                        ║%n", rs.blockedIps));
            sb.append(String.format("║   Blocked Apps:       %12d                        ║%n", rs.blockedApps));
            sb.append(String.format("║   Blocked Domains:    %12d                        ║%n", rs.blockedDomains));
            sb.append(String.format("║   Blocked Ports:      %12d                        ║%n", rs.blockedPorts));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public DPIStats getStats() { return stats; }

    public void printStatus() {
        System.out.println("\n--- Live Status ---");
        System.out.println("Packets: " + stats.totalPackets.get() +
                           " | Forwarded: " + stats.forwardedPackets.get() +
                           " | Dropped: " + stats.droppedPackets.get());
        if (fpManager != null) {
            FPManager.AggregatedStats fp = fpManager.getAggregatedStats();
            System.out.println("Connections: " + fp.totalConnections);
        }
    }
}
