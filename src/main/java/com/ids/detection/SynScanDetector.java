package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

public class SynScanDetector implements Detector {
    private static final String DETECTOR_NAME = "SYN_SCAN_DETECTOR";
    private static final int SYN_FLAG = 0x02;           // TCP SYN flag
    private static final int ACK_FLAG = 0x10;           // TCP ACK flag
    private static final int RST_FLAG = 0x04;           // TCP RST flag
    private static final int FIN_FLAG = 0x01;           // TCP FIN flag
    private static final int PSH_FLAG = 0x08;           // TCP PUSH flag
    private static final int URG_FLAG = 0x20;           // TCP URG flag
    
    private static final int SYN_SCAN_THRESHOLD = 10;   // Alert if 10+ different ports in 5 seconds
    private static final long SCAN_WINDOW_MS = 5000;
    
    private final Map<String, ScanPattern> sourcePatterns = new HashMap<>();

    @Override
    public Optional<AlertEvent> detect(PacketData packet) {
        if (packet == null || !isValidTcpPacket(packet)) {
            return Optional.empty();
        }

        int tcpFlags = packet.getTcpFlags();
        long currentTime = System.currentTimeMillis();
        
        // Detect NULL scan: absolutely no flags set
        if (isSuspiciousNullScan(tcpFlags)) {
            return createAlert(packet, "NULL_SCAN", 
                    "Null scan detected (no TCP flags set)");
        }
        
        // Detect Xmas scan: FIN, PSH, URG flags set
        if (isXmasScan(tcpFlags)) {
            return createAlert(packet, "XMAS_SCAN", 
                    "Xmas scan detected (FIN+PSH+URG flags)");
        }
        
        // Detect FIN scan: FIN flag set without SYN or ACK
        if (isFinScan(tcpFlags)) {
            return createAlert(packet, "FIN_SCAN", 
                    "FIN scan detected");
        }
        
        // Track SYN-only packets for port scan detection
        if (isSynOnly(tcpFlags)) {
            String sourceIP = packet.getSourceIP();
            synchronized (sourcePatterns) {
                ScanPattern pattern = sourcePatterns.computeIfAbsent(sourceIP, k -> new ScanPattern());
                pattern.recordPort(packet.getDestinationPort(), currentTime);
                
                // Clean up old records
                pattern.cleanup(currentTime);
                
                // Check if scan pattern detected
                if (pattern.getUniquePortCount() >= SYN_SCAN_THRESHOLD) {
                    sourcePatterns.remove(sourceIP); // Reset after alert
                    return createAlert(packet, "SYN_SCAN", 
                            String.format("SYN port scan detected: %d unique ports", 
                            pattern.getUniquePortCount()));
                }
            }
        }

        return Optional.empty();
    }

    private boolean isValidTcpPacket(PacketData packet) {
        return packet.getProtocol() != null && 
               packet.getProtocol().equalsIgnoreCase("TCP") &&
               packet.getTcpFlags() >= 0;
    }
    
    private boolean isSuspiciousNullScan(int tcpFlags) {
        // No flags set - highly suspicious
        return (tcpFlags & 0x3F) == 0;
    }
    
    private boolean isXmasScan(int tcpFlags) {
        // FIN + PSH + URG all set
        return (tcpFlags & FIN_FLAG) != 0 && 
               (tcpFlags & PSH_FLAG) != 0 && 
               (tcpFlags & URG_FLAG) != 0;
    }
    
    private boolean isFinScan(int tcpFlags) {
        // FIN set, but not SYN or ACK
        return (tcpFlags & FIN_FLAG) != 0 && 
               (tcpFlags & SYN_FLAG) == 0 && 
               (tcpFlags & ACK_FLAG) == 0;
    }
    
    private boolean isSynOnly(int tcpFlags) {
        // SYN flag set, ACK not set (but other flags might be)
        return (tcpFlags & SYN_FLAG) != 0 && (tcpFlags & ACK_FLAG) == 0;
    }

    private Optional<AlertEvent> createAlert(PacketData packet, String alertType, String details) {
        String severity = "HIGH";
        String message = String.format("%s detected from %s to %s:%d - %s", 
                alertType, packet.getSourceIP(), packet.getDestinationIP(), 
                packet.getDestinationPort(), details);

        AlertEvent alert = new AlertEvent(
                generateAlertId(),
                DETECTOR_NAME,
                severity,
                alertType,
                packet.getSourceIP(),
                packet.getDestinationIP(),
                packet.getSourcePort(),
                packet.getDestinationPort(),
                packet.getProtocol(),
                message,
                System.currentTimeMillis(),
                packet
        );

        return Optional.of(alert);
    }

    private String generateAlertId() {
        return "SYN_" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }
    
    // Track port scanning patterns
    private static class ScanPattern {
        private final Map<Integer, Long> ports = new HashMap<>();
        
        void recordPort(int port, long timestamp) {
            ports.put(port, timestamp);
        }
        
        int getUniquePortCount() {
            return ports.size();
        }
        
        void cleanup(long currentTime) {
            ports.entrySet().removeIf(e -> currentTime - e.getValue() > SCAN_WINDOW_MS);
        }
    }
}
