package com.packetanalyzer.pcap;

import com.packetanalyzer.dpi.DPIEngine;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.List;

/**
 * Captures live network traffic using Pcap4J and feeds it to the DPI Engine.
 */
public class LivePcapCapture {

    private final DPIEngine engine;
    private PcapHandle handle;
    private volatile boolean running = false;

    public LivePcapCapture(DPIEngine engine) {
        this.engine = engine;
    }

    /**
     * Finds an active network interface and starts capturing packets in a blocking loop.
     */
    public void startCapture() throws Exception {
        // Fix for Windows: tell JNA where to find Npcap (if installed without WinPcap compatibility mode)
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            String currentPath = System.getProperty("jna.library.path");
            String npcapPath = "C:\\Windows\\System32\\Npcap";
            if (currentPath == null) {
                System.setProperty("jna.library.path", npcapPath);
            } else if (!currentPath.contains(npcapPath)) {
                System.setProperty("jna.library.path", currentPath + java.io.File.pathSeparator + npcapPath);
            }
        }

        // Find all network interfaces
        List<PcapNetworkInterface> allDevs;
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (java.lang.UnsatisfiedLinkError e) {
            throw new RuntimeException("Npcap or WinPcap is not installed. Please install it (https://npcap.com/) to use live network capture.", e);
        }
        
        if (allDevs == null || allDevs.isEmpty()) {
            throw new RuntimeException("No network interfaces found. Is Npcap/WinPcap installed?");
        }

        // Pick the first interface that has an IPv4 address (usually the active internet connection)
        PcapNetworkInterface device = null;
        for (PcapNetworkInterface dev : allDevs) {
            if (!dev.getAddresses().isEmpty() && !dev.isLoopBack() && dev.getDescription() != null) {
                // Check if it's a real physical/virtual adapter with an IP
                for (PcapAddress addr : dev.getAddresses()) {
                    if (addr.getAddress() instanceof java.net.Inet4Address) {
                        device = dev;
                        break;
                    }
                }
            }
            if (device != null) break;
        }

        if (device == null) {
            // Fallback to the first available non-loopback device
            for (PcapNetworkInterface dev : allDevs) {
                if (!dev.isLoopBack()) {
                    device = dev;
                    break;
                }
            }
        }

        if (device == null) {
            throw new RuntimeException("Could not automatically select a suitable network interface.");
        }

        System.out.println("[LiveCapture] Attaching to interface: " + device.getDescription());

        // Open the interface
        int snapLen = 65536; // Max packet size
        int timeout = 10;    // Milliseconds
        handle = device.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

        running = true;
        System.out.println("[LiveCapture] Capture started successfully.");

        // Loop and capture packets
        while (running) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    RawPacket raw = convertToRawPacket(packet);
                    engine.processLivePacket(raw);
                }
            } catch (Exception e) {
                if (running) {
                    System.err.println("[LiveCapture] Error capturing packet: " + e.getMessage());
                }
            }
        }

        handle.close();
        System.out.println("[LiveCapture] Capture stopped.");
    }

    public void stopCapture() {
        running = false;
        if (handle != null) {
            try { handle.breakLoop(); } catch (Exception ignored) {}
        }
    }

    /**
     * Converts a Pcap4J Packet into our custom RawPacket format
     * so it can be fed directly into the existing DPI parsing logic.
     */
    private RawPacket convertToRawPacket(Packet packet) {
        byte[] rawData = packet.getRawData();
        RawPacket rp = new RawPacket();
        rp.data = rawData;
        rp.header = new PcapPacketHeader();
        rp.header.inclLen = rawData.length;
        rp.header.origLen = rawData.length;
        
        // Use current system time for the timestamp
        long nowMs = System.currentTimeMillis();
        rp.header.tsSec = (int) (nowMs / 1000);
        rp.header.tsUsec = (int) ((nowMs % 1000) * 1000);
        
        return rp;
    }
}
