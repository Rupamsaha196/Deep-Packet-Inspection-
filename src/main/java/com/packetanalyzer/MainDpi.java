package com.packetanalyzer;

import com.packetanalyzer.dpi.DPIEngine;
import com.packetanalyzer.types.AppType;

/**
 * Full DPI Engine entry point with multithreaded packet pipeline.
 * Translated from C++ main_dpi.cpp
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.packetanalyzer.MainDpi -Dexec.args="input.pcap output.pcap [rules.txt]"
 *   java -cp packet-analyzer-fat.jar com.packetanalyzer.MainDpi input.pcap output.pcap
 */
public class MainDpi {

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("   DPI Engine Packet Analyzer v1.0  ");
        System.out.println("====================================\n");

        String inputFile  = "test_dpi.pcap";
        String outputFile = "output_filtered.pcap";
        String rulesFile  = "rules.txt";

        if (args.length >= 2) {
            inputFile  = args[0];
            outputFile = args[1];
        } else {
            System.out.println("No arguments provided. Using defaults: " + inputFile + " -> " + outputFile);
        }
        
        if (args.length >= 3) {
            rulesFile = args[2];
        }

        // ---------------------------------------------------------------
        // Configure the DPI engine
        // ---------------------------------------------------------------
        DPIEngine.Config config = new DPIEngine.Config();
        config.numLoadBalancers = 2;  // 2 load balancers
        config.fpsPerLb         = 2;  // 2 fast-path processors per LB (4 total)
        config.rulesFile        = rulesFile;

        DPIEngine engine = new DPIEngine(config);

        // ---------------------------------------------------------------
        // Example rules (uncomment or modify as needed)
        // ---------------------------------------------------------------
        // engine.blockApp(AppType.TIKTOK);
        // engine.blockApp(AppType.FACEBOOK);
        // engine.blockDomain("*.ads.example.com");
        // engine.blockIP("1.2.3.4");
        // engine.blockPort(8080);   // Would block dst port 8080

        // ---------------------------------------------------------------
        // Run the pipeline
        // ---------------------------------------------------------------
        boolean ok = engine.processFile(inputFile, outputFile);

        if (!ok) {
            System.err.println("\nError: Processing failed.");
            System.exit(1);
        }

        System.out.println("\nDone! Output written to: " + outputFile);
    }

    private static void printUsage(String programName) {
        System.out.println("Usage: " + programName + " <input.pcap> <output.pcap> [rules.txt]");
        System.out.println("\nArguments:");
        System.out.println("  input.pcap  - Source .pcap file to analyze");
        System.out.println("  output.pcap - Destination .pcap file (forwarded packets only)");
        System.out.println("  rules.txt   - (Optional) Blocking rules file");
        System.out.println("\nExample:");
        System.out.println("  " + programName + " capture.pcap filtered.pcap");
        System.out.println("  " + programName + " capture.pcap filtered.pcap rules.txt");
    }
}
