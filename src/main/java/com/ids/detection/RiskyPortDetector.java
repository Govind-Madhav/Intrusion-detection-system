package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class RiskyPortDetector implements Detector {
    private static final String DETECTOR_NAME = "RISKY_PORT_DETECTOR";
    
    private static final Map<Integer, PortInfo> RISKY_PORTS = new HashMap<>();
    
    static {
        // Critical severity ports
        RISKY_PORTS.put(445, new PortInfo("SMB", "CRITICAL"));
        RISKY_PORTS.put(3389, new PortInfo("RDP", "CRITICAL"));
        RISKY_PORTS.put(1433, new PortInfo("MSSQL", "CRITICAL"));
        RISKY_PORTS.put(3306, new PortInfo("MySQL", "CRITICAL"));
        RISKY_PORTS.put(5432, new PortInfo("PostgreSQL", "CRITICAL"));
        RISKY_PORTS.put(27017, new PortInfo("MongoDB", "CRITICAL"));
        
        // High severity ports
        RISKY_PORTS.put(6379, new PortInfo("Redis", "HIGH"));
        RISKY_PORTS.put(9200, new PortInfo("Elasticsearch", "HIGH"));
        RISKY_PORTS.put(5984, new PortInfo("CouchDB", "HIGH"));
        
        // Medium severity ports
        RISKY_PORTS.put(23, new PortInfo("Telnet", "MEDIUM"));
        RISKY_PORTS.put(69, new PortInfo("TFTP", "MEDIUM"));
        RISKY_PORTS.put(135, new PortInfo("RPC", "MEDIUM"));
        RISKY_PORTS.put(139, new PortInfo("NetBIOS", "MEDIUM"));
        RISKY_PORTS.put(50070, new PortInfo("Hadoop", "MEDIUM"));
    }

    @Override
    public Optional<AlertEvent> detect(PacketData packet) {
        if (packet == null || !isValidProtocol(packet)) {
            return Optional.empty();
        }

        int destPort = packet.getDestinationPort();
        
        // Validate port range
        if (destPort < 1 || destPort > 65535) {
            return Optional.empty();
        }
        
        if (RISKY_PORTS.containsKey(destPort)) {
            PortInfo portInfo = RISKY_PORTS.get(destPort);
            return createAlert(packet, portInfo.name, portInfo.severity);
        }

        return Optional.empty();
    }

    private boolean isValidProtocol(PacketData packet) {
        if (packet.getProtocol() == null) return false;
        String protocol = packet.getProtocol().toUpperCase();
        return protocol.equals("TCP") || protocol.equals("UDP");
    }

    private Optional<AlertEvent> createAlert(PacketData packet, String portName, String severity) {
        String message = String.format(
            "Risky port access detected: %s attempting to reach %s:%d (%s) - Severity: %s",
            packet.getSourceIP(), packet.getDestinationIP(), 
            packet.getDestinationPort(), portName, severity
        );

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

    private String generateAlertId() {
        return "PORT_" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }
    
    private static class PortInfo {
        final String name;
        final String severity;
        
        PortInfo(String name, String severity) {
            this.name = name;
            this.severity = severity;
        }
    }
}
