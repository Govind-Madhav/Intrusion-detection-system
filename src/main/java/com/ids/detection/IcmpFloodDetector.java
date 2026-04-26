package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class IcmpFloodDetector implements Detector {
    private static final String DETECTOR_NAME = "ICMP_FLOOD_DETECTOR";
    private static final int THRESHOLD = 50;           // Alert if more than 50 ICMP packets in window
    private static final long WINDOW_MS = 5000;        // 5 second sliding window
    private static final long CLEANUP_INTERVAL_MS = 1000; // Cleanup every second

    private final Map<String, SourceWindow> sourceWindows = new HashMap<>();
    private volatile long lastCleanup = System.currentTimeMillis();

    @Override
    public Optional<AlertEvent> detect(PacketData packet) {
        if (packet == null || !isIcmpPacket(packet)) {
            return Optional.empty();
        }

        String sourceIP = packet.getSourceIP();
        if (sourceIP == null || sourceIP.isEmpty()) {
            return Optional.empty();
        }
        
        long currentTime = System.currentTimeMillis();
        
        // Periodic cleanup to prevent memory leaks
        performCleanup(currentTime);

        synchronized (sourceWindows) {
            SourceWindow window = sourceWindows.computeIfAbsent(sourceIP, k -> new SourceWindow());
            window.addPacket(currentTime);
            
            int count = window.getValidPacketCount(currentTime);

            // Check if threshold exceeded
            if (count > THRESHOLD) {
                String severity = count > 150 ? "CRITICAL" : count > 100 ? "HIGH" : "MEDIUM";
                Optional<AlertEvent> alert = createAlert(packet, count, severity);
                
                // Reset the window after alert to avoid duplicate alerts
                window.reset();
                
                return alert;
            }
        }

        return Optional.empty();
    }
    
    private void performCleanup(long currentTime) {
        if (currentTime - lastCleanup > CLEANUP_INTERVAL_MS) {
            synchronized (sourceWindows) {
                sourceWindows.entrySet().removeIf(e -> {
                    e.getValue().cleanup(currentTime);
                    return e.getValue().isEmpty();
                });
            }
            lastCleanup = currentTime;
        }
    }

    private boolean isIcmpPacket(PacketData packet) {
        if (packet.getProtocol() == null) return false;
        String protocol = packet.getProtocol().toUpperCase();
        return protocol.contains("ICMP");
    }

    private Optional<AlertEvent> createAlert(PacketData packet, int packetCount, String severity) {
        String message = String.format("%d ICMP packets from %s to %s in 5 second window (Possible flood attack)", 
                packetCount, packet.getSourceIP(), packet.getDestinationIP());

        AlertEvent alert = new AlertEvent(
                generateAlertId(),
                DETECTOR_NAME,
                severity,
                "ICMP_FLOOD",
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
        return "ICMP_" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }

    // Proper sliding window with automatic cleanup
    private static class SourceWindow {
        private final Deque<Long> timestamps = new ArrayDeque<>();
        private static final int MAX_CAPACITY = 500; // Maximum timestamps to track

        synchronized void addPacket(long timestamp) {
            timestamps.addLast(timestamp);
            // Prevent unbounded growth
            if (timestamps.size() > MAX_CAPACITY) {
                timestamps.removeFirst();
            }
        }

        synchronized int getValidPacketCount(long currentTime) {
            long windowStart = currentTime - WINDOW_MS;
            int count = 0;
            for (long ts : timestamps) {
                if (ts > windowStart && ts <= currentTime) {
                    count++;
                }
            }
            return count;
        }
        
        synchronized void cleanup(long currentTime) {
            long windowStart = currentTime - WINDOW_MS;
            timestamps.removeIf(ts -> ts <= windowStart);
        }
        
        synchronized boolean isEmpty() {
            return timestamps.isEmpty();
        }
        
        synchronized void reset() {
            timestamps.clear();
        }
    }
}
