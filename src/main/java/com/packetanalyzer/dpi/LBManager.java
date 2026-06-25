package com.packetanalyzer.dpi;

import com.packetanalyzer.types.*;

import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Manages a pool of LoadBalancer instances.
 * Translated from C++ class LBManager in load_balancer.h / load_balancer.cpp
 */
public class LBManager {

    public static class AggregatedStats {
        public long totalReceived;
        public long totalDispatched;
    }

    private final int                fps_per_lb;
    private final List<LoadBalancer> lbs = new ArrayList<>();

    public LBManager(int numLbs, int fpsPerLb,
                     List<LinkedBlockingQueue<PacketJob>> fpQueues) {
        this.fps_per_lb = fpsPerLb;

        for (int lbId = 0; lbId < numLbs; lbId++) {
            int fpStart = lbId * fpsPerLb;
            List<LinkedBlockingQueue<PacketJob>> lbFpQueues = new ArrayList<>();
            for (int i = 0; i < fpsPerLb; i++) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
            }
            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.println("[LBManager] Created " + numLbs +
                           " load balancers, " + fpsPerLb + " FPs each");
    }

    public void startAll() { for (LoadBalancer lb : lbs) lb.start(); }
    public void stopAll()  { for (LoadBalancer lb : lbs) lb.stop(); }

    /**
     * Select the LB for a given five-tuple using a top-level hash.
     * Translated from LBManager::getLBForPacket()
     */
    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int lbIndex = Math.abs(tuple.hashCode() % lbs.size());
        return lbs.get(lbIndex);
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats s = lb.getStats();
            stats.totalReceived   += s.packetsReceived;
            stats.totalDispatched += s.packetsDispatched;
        }
        return stats;
    }
}
