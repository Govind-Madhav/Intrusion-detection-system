package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class RiskyPortDetector implements Detector {
    private static final String DETECTOR_NAME = "RISKY_PORT_DETECTOR";

    // Define risky ports (commonly used by malware or for scanning)
    private static final Set<Integer> RISKY_PORTS = new HashSet<>();
    
    static {
        // Common backdoor/exploitation ports
        RISKY_PORTS.add(23);    // Telnet
        RISKY_PORTS.add(69);    // TFTP
        RISKY_PORTS.add(135);   // RPC
        RISKY_PORTS.add(139);   // NetBIOS
        RISKY_PORTS.add(445);   // SMB
        RISKY_PORTS.add(1433);  // MSSQL
        RISKY_PORTS.add(3306);  // MySQL
        RISKY_PORTS.add(3389);  // RDP
        RISKY_PORTS.add(5432);  // PostgreSQL
        RISKY_PORTS.add(5984);  // CouchDB
        RISKY_PORTS.add(6379);  // Redis
        RISKY_PORTS.add(9200);  // Elasticsearch
        RISKY_PORTS.add(27017); // MongoDB
        RISKY_PORTS.add(50070); // Hadoop NameNode
    }

    @Override
    public Optional<AlertEvent> detect(PacketData packet) {
        if (packet == null || !isTcpOrUdp(packet)) {
            return Optional.empty();
        }

        int destPort = packet.getDestinationPort();
        
        if (RISKY_PORTS.contains(destPort)) {
            return createAlert(packet);
        }

        return Optional.empty();
    }

    private boolean isTcpOrUdp(PacketData packet) {
        if (packet.getProtocol() == null) return false;
        String protocol = packet.getProtocol().toUpperCase();
        return protocol.equals("TCP") || protocol.equals("UDP");
    }

    private Optional<AlertEvent> createAlert(PacketData packet) {
        String portName = getPortName(packet.getDestinationPort());
        String severity = calculateSeverity(packet.getDestinationPort());
        String message = String.format("Connection attempt to risky port: %d (%s) from %s", 
                packet.getDestinationPort(), portName, packet.getSourceIP());

        AlertEvent alert = new AlertEvent(
                generateAlertId(),
                DETECTOR_NAME,
                severity,
                "RISKY_PORT_ACCESS",
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

    private String calculateSeverity(int port) {
        // Critical ports: SMB, RDP, database ports
        if (port == 445 || port == 3389 || port == 1433 || port == 3306 || port == 5432 || port == 27017) {
            return "CRITICAL";
        }
        // High severity: other database and service ports
        if (port == 6379 || port == 9200 || port == 5984) {
            return "HIGH";
        }
        // Medium severity: other risky ports
        return "MEDIUM";
    }

    private String getPortName(int port) {
        return switch (port) {
            case 23 -> "Telnet";
            case 69 -> "TFTP";
            case 135 -> "RPC";
            case 139 -> "NetBIOS";
            case 445 -> "SMB";
            case 1433 -> "MSSQL";
            case 3306 -> "MySQL";
            case 3389 -> "RDP";
            case 5432 -> "PostgreSQL";
            case 5984 -> "CouchDB";
            case 6379 -> "Redis";
            case 9200 -> "Elasticsearch";
            case 27017 -> "MongoDB";
            case 50070 -> "Hadoop";
            default -> "Unknown";
        };
    }

    private String generateAlertId() {
        return "PORT_" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }
}
