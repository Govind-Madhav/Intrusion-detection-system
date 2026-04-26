package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class IcmpFloodDetector implements Detector {
    private static final String DETECTOR_NAME = "ICMP_FLOOD_DETECTOR";
    private static final int THRESHOLD = 50;           // Alert if more than 50 ICMP packets in window
    private static final long WINDOW_MS = 5000;        // 5 second sliding window

    private final ConcurrentHashMap<String, PacketWindow> sourceWindows = new ConcurrentHashMap<>();

    @Override
    public Optional<AlertEvent> detect(PacketData packet) {
        if (packet == null || !isIcmpPacket(packet)) {
            return Optional.empty();
        }

        String sourceIP = packet.getSourceIP();
        long currentTime = System.currentTimeMillis();

        PacketWindow window = sourceWindows.computeIfAbsent(sourceIP, k -> new PacketWindow());
        window.addPacket(currentTime);

        // Check if threshold exceeded
        if (window.getCount(currentTime) > THRESHOLD) {
            return createAlert(packet, window.getCount(currentTime));
        }

        return Optional.empty();
    }

    private boolean isIcmpPacket(PacketData packet) {
        if (packet.getProtocol() == null) return false;
        String protocol = packet.getProtocol().toUpperCase();
        return protocol.contains("ICMP");
    }

    private Optional<AlertEvent> createAlert(PacketData packet, int packetCount) {
        String severity = packetCount > 100 ? "CRITICAL" : "HIGH";
        String message = String.format("ICMP Flood detected: %d packets from %s in 5 second window", 
                packetCount, packet.getSourceIP());

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

    // Helper class for sliding window tracking
    private static class PacketWindow {
        private final long[] timestamps = new long[1000];
        private int index = 0;
        private final AtomicInteger count = new AtomicInteger(0);

        synchronized void addPacket(long currentTime) {
            timestamps[index % 1000] = currentTime;
            index++;
            count.incrementAndGet();
        }

        synchronized int getCount(long currentTime) {
            long windowStart = currentTime - 5000; // 5 second window
            int validCount = 0;

            for (long ts : timestamps) {
                if (ts > windowStart && ts <= currentTime) {
                    validCount++;
                }
            }
            return validCount;
        }
    }
}
