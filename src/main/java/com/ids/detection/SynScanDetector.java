package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.Optional;
import java.util.UUID;

public class SynScanDetector implements Detector {
    private static final String DETECTOR_NAME = "SYN_SCAN_DETECTOR";
    private static final int SYN_FLAG = 0x02;           // TCP SYN flag
    private static final int ACK_FLAG = 0x10;           // TCP ACK flag
    private static final int RST_FLAG = 0x04;           // TCP RST flag
    private static final int FIN_FLAG = 0x01;           // TCP FIN flag

    @Override
    public Optional<AlertEvent> detect(PacketData packet) {
        if (packet == null || !isValidTcpPacket(packet)) {
            return Optional.empty();
        }

        int tcpFlags = packet.getTcpFlags();
        
        // Detect SYN scan: SYN flag set, ACK not set (potential port scan)
        boolean isSynOnly = (tcpFlags & SYN_FLAG) != 0 && (tcpFlags & ACK_FLAG) == 0;
        
        // Detect null scan: no flags set
        boolean isNullScan = (tcpFlags & 0x3F) == 0;
        
        // Detect FIN scan: FIN flag set, SYN and ACK not set
        boolean isFinScan = (tcpFlags & FIN_FLAG) != 0 && (tcpFlags & SYN_FLAG) == 0 && (tcpFlags & ACK_FLAG) == 0;

        if (isSynOnly || isNullScan || isFinScan) {
            return createAlert(packet, tcpFlags);
        }

        return Optional.empty();
    }

    private boolean isValidTcpPacket(PacketData packet) {
        return packet.getProtocol() != null && 
               packet.getProtocol().equalsIgnoreCase("TCP") &&
               packet.getTcpFlags() > 0;
    }

    private Optional<AlertEvent> createAlert(PacketData packet, int tcpFlags) {
        String alertType = determineScanType(tcpFlags);
        String severity = "HIGH";
        String message = String.format("Potential %s detected from %s to %s:%d", 
                alertType, packet.getSourceIP(), packet.getDestinationIP(), packet.getDestinationPort());

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

    private String determineScanType(int tcpFlags) {
        if ((tcpFlags & FIN_FLAG) != 0) return "FIN_SCAN";
        if ((tcpFlags & 0x3F) == 0) return "NULL_SCAN";
        return "SYN_SCAN";
    }

    private String generateAlertId() {
        return "SYN_" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public String getName() {
        return DETECTOR_NAME;
    }
}
