package com.packetanalyzer.api;

import com.packetanalyzer.DashboardApp;
import com.packetanalyzer.types.DPIStats;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        Map<String, Object> response = new HashMap<>();
        
        if (DashboardApp.engine != null) {
            DPIStats stats = DashboardApp.engine.getStats();
            response.put("totalPackets", stats.totalPackets.get());
            response.put("totalBytes", stats.totalBytes.get());
            response.put("tcpPackets", stats.tcpPackets.get());
            response.put("udpPackets", stats.udpPackets.get());
            response.put("otherPackets", stats.otherPackets.get());
            response.put("droppedPackets", stats.droppedPackets.get());
            response.put("activeConnections", stats.activeConnections.get());
        } else {
            response.put("error", "DPI Engine not initialized");
        }
        
        return response;
    }

    @GetMapping("/logs")
    public List<String> getLogs() {
        return new ArrayList<>(DashboardApp.recentLogs);
    }
}
