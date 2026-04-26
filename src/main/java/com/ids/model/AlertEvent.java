package com.ids.model;

import java.time.Instant;

public class AlertEvent {
    private final String alertId;
    private final String detectorName;
    private final String severity;          // LOW, MEDIUM, HIGH, CRITICAL
    private final String alertType;         // e.g., "SYN_SCAN", "ICMP_FLOOD", "RISKY_PORT"
    private final String sourceIP;
    private final String destinationIP;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;
    private final String message;
    private final long timestamp;
    private final PacketData triggeringPacket;

    public AlertEvent(String alertId, String detectorName, String severity, String alertType,
                      String sourceIP, String destinationIP, int sourcePort, int destinationPort,
                      String protocol, String message, long timestamp, PacketData triggeringPacket) {
        this.alertId = alertId;
        this.detectorName = detectorName;
        this.severity = severity;
        this.alertType = alertType;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.message = message;
        this.timestamp = timestamp;
        this.triggeringPacket = triggeringPacket;
    }

    public String getAlertId() { return alertId; }
    public String getDetectorName() { return detectorName; }
    public String getSeverity() { return severity; }
    public String getAlertType() { return alertType; }
    public String getSourceIP() { return sourceIP; }
    public String getDestinationIP() { return destinationIP; }
    public int getSourcePort() { return sourcePort; }
    public int getDestinationPort() { return destinationPort; }
    public String getProtocol() { return protocol; }
    public String getMessage() { return message; }
    public long getTimestamp() { return timestamp; }
    public PacketData getTriggeringPacket() { return triggeringPacket; }

    @Override
    public String toString() {
        return "AlertEvent{" +
                "alertId='" + alertId + '\'' +
                ", detectorName='" + detectorName + '\'' +
                ", severity='" + severity + '\'' +
                ", alertType='" + alertType + '\'' +
                ", sourceIP='" + sourceIP + '\'' +
                ", destinationIP='" + destinationIP + '\'' +
                ", sourcePort=" + sourcePort +
                ", destinationPort=" + destinationPort +
                ", protocol='" + protocol + '\'' +
                ", message='" + message + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
