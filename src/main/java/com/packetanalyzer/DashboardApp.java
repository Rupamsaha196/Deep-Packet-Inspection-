package com.packetanalyzer;

import com.packetanalyzer.dpi.DPIEngine;
import com.packetanalyzer.pcap.LivePcapCapture;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.concurrent.ConcurrentLinkedQueue;

@SpringBootApplication
public class DashboardApp {

    // Global references for the API Controller to access
    public static DPIEngine engine;
    public static final ConcurrentLinkedQueue<String> recentLogs = new ConcurrentLinkedQueue<>();

    public static void main(String[] args) {
        // 1. Initialize DPI Engine
        DPIEngine.Config config = new DPIEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        config.rulesFile = "rules.txt"; // Load the blocking rules
        
        engine = new DPIEngine(config);
        
        if (!engine.initialize()) {
            System.err.println("[DashboardApp] Failed to initialize DPI engine.");
            return;
        }
        engine.start();

        // 2. Start Live Capture in a background thread
        Thread captureThread = new Thread(() -> {
            try {
                System.out.println("[DashboardApp] Starting live network capture...");
                LivePcapCapture liveCapture = new LivePcapCapture(engine);
                liveCapture.startCapture();
            } catch (Exception e) {
                System.err.println("\n--------------------------------------------------");
                System.err.println("[DashboardApp] Live capture failed!");
                System.err.println("Cause: " + e.getMessage());
                System.err.println("--------------------------------------------------\n");
            }
        });
        captureThread.setDaemon(true);
        captureThread.start();
        
        System.out.println("==================================================");
        System.out.println("  Web Dashboard running at: http://localhost:8080 ");
        System.out.println("==================================================");

        // 3. Initialize Spring Boot (This blocks the main thread!)
        SpringApplication.run(DashboardApp.class, args);
    }
    
    /**
     * Add a log entry to be displayed on the dashboard.
     * Keeps only the last 100 logs.
     */
    public static void addLog(String log) {
        recentLogs.add(log);
        while (recentLogs.size() > 100) {
            recentLogs.poll();
        }
    }
}
