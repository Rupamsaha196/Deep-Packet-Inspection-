package com.packetanalyzer.dpi;

import com.packetanalyzer.types.*;

import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Receives packets from the reader and distributes them to FastPath queues
 * using five-tuple hash-based load balancing.
 * Translated from C++ class LoadBalancer in load_balancer.h / load_balancer.cpp
 */
public class LoadBalancer {

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public long[] perFpPackets;
    }

    private final int                              lbId;
    private final int                              fpStartId;
    private final int                              numFps;
    private final LinkedBlockingQueue<PacketJob>   inputQueue = new LinkedBlockingQueue<>(10_000);
    private final List<LinkedBlockingQueue<PacketJob>> fpQueues;
    private final long[]                           perFpCounts;

    private volatile boolean running = false;
    private Thread           thread;

    private final AtomicLong packetsReceived   = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);

    public LoadBalancer(int lbId,
                        List<LinkedBlockingQueue<PacketJob>> fpQueues,
                        int fpStartId) {
        this.lbId      = lbId;
        this.fpQueues  = fpQueues;
        this.fpStartId = fpStartId;
        this.numFps    = fpQueues.size();
        this.perFpCounts = new long[numFps];
    }

    /** Start the LB dispatching thread. Translated from LoadBalancer::start() */
    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "LB-" + lbId);
        thread.setDaemon(true);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId +
                           "-FP" + (fpStartId + numFps - 1) + ")");
    }

    /** Stop the LB thread. Translated from LoadBalancer::stop() */
    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.offer(new PacketJob()); // wake up
        if (thread != null) {
            try { thread.join(2000); } catch (InterruptedException ignored) {}
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    private void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null || job.tuple == null) continue;

                packetsReceived.incrementAndGet();

                int fpIndex = selectFP(job.tuple);
                fpQueues.get(fpIndex).put(job);

                packetsDispatched.incrementAndGet();
                perFpCounts[fpIndex]++;

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Select a FP index using the five-tuple hash.
     * Translated from LoadBalancer::selectFP()
     */
    private int selectFP(FiveTuple tuple) {
        int hash = tuple.hashCode();
        return Math.abs(hash % numFps);
    }

    public LinkedBlockingQueue<PacketJob> getInputQueue() { return inputQueue; }

    public LBStats getStats() {
        LBStats s = new LBStats();
        s.packetsReceived   = packetsReceived.get();
        s.packetsDispatched = packetsDispatched.get();
        s.perFpPackets      = Arrays.copyOf(perFpCounts, perFpCounts.length);
        return s;
    }
}
