package com.packetanalyzer.rules;

import com.packetanalyzer.types.AppType;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Manages blocking rules for IPs, applications, domains, and ports.
 * Translated from C++ class RuleManager in rule_manager.h / rule_manager.cpp
 *
 * Key translation notes:
 *  - std::unordered_set  -> HashSet
 *  - std::shared_mutex   -> ReentrantReadWriteLock (read/write lock)
 *  - std::shared_lock    -> readLock()
 *  - std::unique_lock    -> writeLock()
 *  - std::optional<BlockReason> -> Optional<BlockReason>
 */
public class RuleManager {

    // -------------------------------------------------------------------------
    // Inner types (was nested structs in rule_manager.h)
    // -------------------------------------------------------------------------

    public enum BlockReasonType { IP, APP, DOMAIN, PORT }

    public static class BlockReason {
        public final BlockReasonType type;
        public final String          detail;

        public BlockReason(BlockReasonType type, String detail) {
            this.type   = type;
            this.detail = detail;
        }
    }

    public static class RuleStats {
        public long blockedIps;
        public long blockedApps;
        public long blockedDomains;
        public long blockedPorts;
    }

    // -------------------------------------------------------------------------
    // State — each category has its own ReadWriteLock
    // -------------------------------------------------------------------------

    private final Set<Long>     blockedIps      = new HashSet<>();
    private final ReadWriteLock ipLock          = new ReentrantReadWriteLock();

    private final Set<AppType>  blockedApps     = new HashSet<>();
    private final ReadWriteLock appLock         = new ReentrantReadWriteLock();

    private final Set<String>   blockedDomains  = new HashSet<>();
    private final List<String>  domainPatterns  = new ArrayList<>();
    private final ReadWriteLock domainLock      = new ReentrantReadWriteLock();

    private final Set<Integer>  blockedPorts    = new HashSet<>();
    private final ReadWriteLock portLock        = new ReentrantReadWriteLock();

    // -------------------------------------------------------------------------
    // IP blocking
    // -------------------------------------------------------------------------

    /** Block by raw uint32 IP (stored as long). */
    public void blockIP(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    /** Block by dotted-decimal IP string. */
    public void blockIP(String ip) { blockIP(parseIP(ip)); }

    public void unblockIP(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void unblockIP(String ip) { unblockIP(parseIP(ip)); }

    public boolean isIPBlocked(long ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (long ip : blockedIps) result.add(ipToString(ip));
            return result;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // -------------------------------------------------------------------------
    // Application blocking
    // -------------------------------------------------------------------------

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.toDisplayString());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + app.toDisplayString());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // -------------------------------------------------------------------------
    // Domain blocking (supports wildcard patterns like *.example.com)
    // -------------------------------------------------------------------------

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {
            // Exact match
            if (blockedDomains.contains(domain)) return true;

            // Pattern match (case-insensitive)
            String lower = domain.toLowerCase();
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern.toLowerCase())) return true;
            }
            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    /**
     * Wildcard domain match (handles *.example.com).
     * Translated from RuleManager::domainMatchesPattern()
     */
    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            // domain ends with suffix
            if (domain.length() >= suffix.length() &&
                domain.endsWith(suffix)) return true;
            // bare domain match (example.com matches *.example.com)
            if (domain.equals(pattern.substring(2))) return true;
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Port blocking
    // -------------------------------------------------------------------------

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port & 0xFFFF);
            System.out.println("[RuleManager] Blocked port: " + (port & 0xFFFF));
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port & 0xFFFF);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port & 0xFFFF);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // -------------------------------------------------------------------------
    // Combined check
    // -------------------------------------------------------------------------

    /**
     * Check all rules and return the first match, or empty if packet should pass.
     * Translated from RuleManager::shouldBlock()
     */
    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort,
                                              AppType app, String domain) {
        if (isIPBlocked(srcIp))
            return Optional.of(new BlockReason(BlockReasonType.IP, ipToString(srcIp)));

        if (isPortBlocked(dstPort))
            return Optional.of(new BlockReason(BlockReasonType.PORT,
                                               String.valueOf(dstPort & 0xFFFF)));

        if (isAppBlocked(app))
            return Optional.of(new BlockReason(BlockReasonType.APP, app.toDisplayString()));

        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain))
            return Optional.of(new BlockReason(BlockReasonType.DOMAIN, domain));

        return Optional.empty();
    }

    // -------------------------------------------------------------------------
    // Persistence — save / load rules from a simple text file
    // -------------------------------------------------------------------------

    /**
     * Save all rules to a text file.
     * Translated from RuleManager::saveRules()
     */
    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) pw.println(ip);

            pw.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) pw.println(app.toDisplayString());

            pw.println("\n[BLOCKED_DOMAINS]");
            for (String d : getBlockedDomains()) pw.println(d);

            pw.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) pw.println(port);
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Load rules from a text file (same format as saveRules).
     * Translated from RuleManager::loadRules()
     */
    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";

            while ((line = br.readLine()) != null) {
                if (line.isBlank()) continue;

                if (line.startsWith("[")) {
                    section = line.trim();
                    continue;
                }

                switch (section) {
                    case "[BLOCKED_IPS]"     -> blockIP(line.trim());
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line.trim());
                    case "[BLOCKED_PORTS]"   -> blockPort(Integer.parseInt(line.trim()));
                    case "[BLOCKED_APPS]"    -> {
                        for (AppType app : AppType.values()) {
                            if (app.toDisplayString().equals(line.trim())) {
                                blockApp(app);
                                break;
                            }
                        }
                    }
                }
            }

            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Clear all rules. */
    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIps.clear();     } finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();    try { blockedApps.clear();    } finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear();   } finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        RuleStats s = new RuleStats();
        ipLock.readLock().lock();     try { s.blockedIps     = blockedIps.size();                              } finally { ipLock.readLock().unlock(); }
        appLock.readLock().lock();    try { s.blockedApps    = blockedApps.size();                             } finally { appLock.readLock().unlock(); }
        domainLock.readLock().lock(); try { s.blockedDomains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }
        portLock.readLock().lock();   try { s.blockedPorts   = blockedPorts.size();                           } finally { portLock.readLock().unlock(); }
        return s;
    }

    // -------------------------------------------------------------------------
    // IP address helpers (translated from RuleManager::parseIP / ipToString)
    // -------------------------------------------------------------------------

    /** Parse dotted-decimal IP string to a uint32 value stored as long. */
    public static long parseIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Long.parseLong(parts[i].trim()) << (i * 8));
        }
        return result;
    }

    /** Convert a uint32 IP (stored as long) to dotted-decimal string. */
    public static String ipToString(long ip) {
        return (ip & 0xFF)        + "." +
               ((ip >> 8)  & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }
}
