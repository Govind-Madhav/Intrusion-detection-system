package com.ids.app;

import com.ids.capture.InterfaceSelector;
import com.ids.capture.PacketCaptureService;
import com.ids.config.AppConfig;
import com.ids.config.CliArgs;
import com.ids.detection.DetectionEngine;
import com.ids.model.AlertEvent;
import com.ids.model.PacketData;
import com.ids.output.AlertLogger;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.NotOpenException;

import java.util.List;
import java.util.stream.Collectors;

public class Application {

    public static void main(String[] args) {
        AlertLogger alertLogger = null;
        
        try {
            // Load configuration from environment
            AppConfig.loadConfig();
            
            CliArgs cliArgs = CliArgs.parse(args);
            
            if (cliArgs.isVerbose()) {
                System.out.println("[DEBUG] Configuration: " + cliArgs);
                AppConfig.printConfig();
            }

            // Initialize alert logger
            alertLogger = new AlertLogger(
                    AppConfig.getLogFilePath(),
                    AppConfig.isConsoleLoggingEnabled()
            );
            
            System.out.println("[INFO] Intrusion Detection System Started");

            // Select interface
            PcapNetworkInterface networkInterface = InterfaceSelector.select(cliArgs.getInterfaceName());
            System.out.printf("[INFO] Capturing %d packets from interface: %s (%s)%n",
                    cliArgs.getPacketCount(), networkInterface.getName(), networkInterface.getDescription());

            // Perform capture
            long startTime = System.currentTimeMillis();
            try (PacketCaptureService captureService = new PacketCaptureService(cliArgs.getSnapLen(), cliArgs.getTimeoutMillis())) {
                List<PacketData> packets = captureService.capture(networkInterface, cliArgs.getPacketCount());
                long duration = System.currentTimeMillis() - startTime;

                // Report statistics
                PacketCaptureService.CaptureStatistics stats = captureService.getStatistics();
                System.out.printf("[INFO] Captured %d packets in %dms (failed: %d)%n", 
                        stats.processed, duration, stats.failed);

                if (packets.isEmpty()) {
                    System.out.println("[WARN] No packets were captured within the timeout period.");
                    return;
                }

                // Output captured packets (verbose mode)
                if (cliArgs.isVerbose()) {
                    System.out.println("[DEBUG] Detailed packet output:");
                    for (PacketData packet : packets) {
                        System.out.println(packet);
                    }
                }
                
                // Run detection analysis
                System.out.println("[INFO] Starting threat detection analysis...");
                DetectionEngine detectionEngine = new DetectionEngine();
                long analysisStart = System.currentTimeMillis();
                
                List<AlertEvent> allAlerts = detectionEngine.analyzePackets(packets);
                
                long analysisTime = System.currentTimeMillis() - analysisStart;
                System.out.printf("[INFO] Analysis completed in %dms%n", analysisTime);
                
                // Filter alerts by minimum severity
                String minSeverity = AppConfig.getMinSeverity();
                List<AlertEvent> filteredAlerts = filterAlertsBySeverity(allAlerts, minSeverity);
                
                // Log alerts
                if (!filteredAlerts.isEmpty()) {
                    System.out.printf("[WARNING] Detected %d threats (severity >= %s)%n", 
                            filteredAlerts.size(), minSeverity);
                    alertLogger.logBatch(filteredAlerts);
                } else {
                    System.out.println("[INFO] No threats detected.");
                }
                
                // Summary
                System.out.printf("[INFO] Analysis Summary:%n");
                System.out.printf("  - Packets Captured: %d%n", packets.size());
                System.out.printf("  - Packets Analyzed: %d%n", allAlerts.size() + (packets.size() - allAlerts.size()));
                System.out.printf("  - Threats Detected: %d (filtered to %d by severity)%n", 
                        allAlerts.size(), filteredAlerts.size());
                System.out.printf("  - Detection Engines: %d%n", detectionEngine.getDetectorCount());
                
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println("[ERROR] " + e.getMessage());
            try {
                InterfaceSelector.printAvailableInterfaces();
            } catch (PcapNativeException ignored) {
                System.err.println("[ERROR] Unable to list interfaces.");
            }
            System.exit(1);
        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("[ERROR] Packet capture failed: " + e.getMessage());
            System.exit(1);
        } finally {
            // Cleanup
            if (alertLogger != null) {
                alertLogger.close();
                System.out.println("[INFO] Intrusion Detection System Stopped");
            }
        }
    }
    
    /**
     * Filter alerts by severity level
     *
     * @param alerts list of all alerts
     * @param minSeverity minimum severity level (LOW, MEDIUM, HIGH, CRITICAL)
     * @return filtered alerts
     */
    private static List<AlertEvent> filterAlertsBySeverity(List<AlertEvent> alerts, String minSeverity) {
        if (alerts == null || alerts.isEmpty()) {
            return List.of();
        }
        
        int minSeverityLevel = getSeverityLevel(minSeverity);
        return alerts.stream()
                .filter(alert -> getSeverityLevel(alert.getSeverity()) >= minSeverityLevel)
                .collect(Collectors.toList());
    }
    
    /**
     * Convert severity string to numeric level
     *
     * @param severity severity string
     * @return severity level (higher number = more severe)
     */
    private static int getSeverityLevel(String severity) {
        return switch (severity) {
            case "LOW" -> 1;
            case "MEDIUM" -> 2;
            case "HIGH" -> 3;
            case "CRITICAL" -> 4;
            default -> 0;
        };
    }
}
