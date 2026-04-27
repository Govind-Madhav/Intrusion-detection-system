package com.ids.capture;

import com.ids.api.AlertDto;
import com.ids.api.AlertStore;
import com.ids.detection.DetectionEngine;
import com.ids.model.AlertEvent;
import com.ids.model.PacketData;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * this service listens to the wifi/ethernet card to get real packets
 * then it passes them to the engine to check for hacks
 * 
 * note: you need to install Npcap on windows for this to work
 */
@Service
public class LiveCaptureService {

    private static final Logger log = LoggerFactory.getLogger(LiveCaptureService.class);

    private static final int SNAP_LEN      = 65536;
    private static final int TIMEOUT_MS    = 50;     // short timeout so we can stop it easily

    @Autowired private AlertStore            alertStore;
    @Autowired private SimpMessagingTemplate messaging;

    private final DetectionEngine detectionEngine = new DetectionEngine();

    // State
    private final AtomicBoolean running       = new AtomicBoolean(false);
    private final AtomicLong    packetsTotal  = new AtomicLong(0);
    private final AtomicLong    alertsTotal   = new AtomicLong(0);
    private volatile String     activeIface   = null;
    private volatile String     errorMessage  = null;
    private volatile Thread     captureThread = null;

    // ==========================================
    // main methods to start/stop the capture
    // ==========================================

    /**
     * starts listening on the selected interface like Wi-Fi
     */
    public synchronized boolean start(String interfaceName) {
        if (running.get()) {
            log.warn("[LIVE] Already capturing on {}", activeIface);
            return false;
        }

        PcapNetworkInterface nif;
        try {
            nif = InterfaceSelector.select(interfaceName);
        } catch (PcapNativeException | IllegalArgumentException | IllegalStateException e) {
            errorMessage = "Interface not found: " + e.getMessage();
            log.error("[LIVE] {}", errorMessage);
            return false;
        }

        packetsTotal.set(0);
        alertsTotal.set(0);
        errorMessage = null;
        activeIface  = nif.getDescription() != null ? nif.getDescription() : nif.getName();
        running.set(true);

        captureThread = new Thread(() -> captureLoop(nif), "live-capture");
        captureThread.setDaemon(true);
        captureThread.start();

        log.info("[LIVE] Started capture on: {}", activeIface);
        return true;
    }

    // stops the background thread
    public synchronized void stop() {
        if (!running.getAndSet(false)) return;
        if (captureThread != null) {
            captureThread.interrupt();
            captureThread = null;
        }
        log.info("[LIVE] Stopped capture. Packets={} Alerts={}", packetsTotal.get(), alertsTotal.get());
        activeIface = null;
    }

    public boolean isRunning()     { return running.get(); }
    public long    getPackets()    { return packetsTotal.get(); }
    public long    getAlerts()     { return alertsTotal.get(); }
    public String  getActiveIface(){ return activeIface; }
    public String  getError()      { return errorMessage; }

    // get all the network cards for the frontend dropdown
    public List<String> listInterfaces() {
        try {
            return InterfaceSelector.listAllInterfaces().stream()
                    .map(n -> {
                        String desc = n.getDescription();
                        return (desc != null && !desc.isBlank()) ? desc : n.getName();
                    })
                    .toList();
        } catch (PcapNativeException e) {
            log.error("[LIVE] Could not enumerate interfaces: {}", e.getMessage());
            return List.of();
        }
    }

    // ==========================================
    // the main while loop that runs in the background
    // ==========================================

    private void captureLoop(PcapNetworkInterface nif) {
        PcapHandle handle = null;
        try {
            handle = nif.openLive(SNAP_LEN, PromiscuousMode.PROMISCUOUS, TIMEOUT_MS);
            log.info("[LIVE] Handle opened — listening for packets");

            while (running.get() && !Thread.currentThread().isInterrupted()) {
                Packet pkt = handle.getNextPacket();
                if (pkt == null) continue;   // no packet arrived in 50ms, try again

                packetsTotal.incrementAndGet();
                try {
                    PacketData pd = convert(pkt);
                    List<AlertEvent> alerts = detectionEngine.analyze(pd);
                    for (AlertEvent event : alerts) {
                        AlertDto dto = toDto(event);
                        alertStore.add(dto);
                        messaging.convertAndSend("/topic/alerts", dto);
                        alertsTotal.incrementAndGet();
                        log.info("[LIVE] Alert: {} [{}] from {}", event.getAlertType(), event.getSeverity(), event.getSourceIP());
                    }
                } catch (Exception e) {
                    // if a packet is broken dont crash the whole system
                    log.debug("[LIVE] Packet processing error: {}", e.getMessage());
                }
            }

        } catch (PcapNativeException | NotOpenException e) {
            errorMessage = e.getMessage();
            log.error("[LIVE] Capture error: {}", errorMessage);
        } finally {
            running.set(false);
            if (handle != null) {
                try { handle.close(); } catch (Exception ignored) {}
            }
            log.info("[LIVE] Capture thread exited");
        }
    }

    // ==========================================
    // convert pcap4j packet to our custom packet data
    // ==========================================

    private PacketData convert(Packet packet) {
        String srcIp = "", dstIp = "", protocol = "Unknown", packetType = "Unknown";
        int srcPort = 0, dstPort = 0, tcpFlags = 0;
        boolean malformed = false;

        try {
            EthernetPacket eth = packet.get(EthernetPacket.class);
            if (eth != null) packetType = "Ethernet";

            IpV4Packet ipv4 = packet.get(IpV4Packet.class);
            IpV6Packet ipv6 = packet.get(IpV6Packet.class);

            if (ipv4 != null) {
                srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
                dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
                packetType = "IPv4";
            } else if (ipv6 != null) {
                srcIp = ipv6.getHeader().getSrcAddr().getHostAddress();
                dstIp = ipv6.getHeader().getDstAddr().getHostAddress();
                packetType = "IPv6";
            } else if (packet.get(ArpPacket.class) != null) {
                packetType = "ARP";
            }

            TcpPacket          tcp    = packet.get(TcpPacket.class);
            UdpPacket          udp    = packet.get(UdpPacket.class);
            IcmpV4CommonPacket icmpv4 = packet.get(IcmpV4CommonPacket.class);
            IcmpV6CommonPacket icmpv6 = packet.get(IcmpV6CommonPacket.class);

            if (tcp != null) {
                protocol = "TCP";
                srcPort  = tcp.getHeader().getSrcPort().valueAsInt();
                dstPort  = tcp.getHeader().getDstPort().valueAsInt();
                tcpFlags = buildFlags(tcp.getHeader());
            } else if (udp != null) {
                protocol = "UDP";
                srcPort  = udp.getHeader().getSrcPort().valueAsInt();
                dstPort  = udp.getHeader().getDstPort().valueAsInt();
            } else if (icmpv4 != null) {
                protocol = "ICMPv4";
            } else if (icmpv6 != null) {
                protocol = "ICMPv6";
            } else if (ipv4 != null) {
                protocol = ipv4.getHeader().getProtocol().name();
            }

        } catch (Exception e) {
            malformed = true;
        }

        return new PacketData(srcIp, dstIp, protocol, srcPort, dstPort,
                packet.length(), System.currentTimeMillis(),
                new byte[0], tcpFlags, "", "", "", packetType, malformed);
    }

    private int buildFlags(TcpPacket.TcpHeader h) {
        int f = 0;
        if (Boolean.TRUE.equals(h.getFin())) f |= 0x01;
        if (Boolean.TRUE.equals(h.getSyn())) f |= 0x02;
        if (Boolean.TRUE.equals(h.getRst())) f |= 0x04;
        if (Boolean.TRUE.equals(h.getPsh())) f |= 0x08;
        if (Boolean.TRUE.equals(h.getAck())) f |= 0x10;
        if (Boolean.TRUE.equals(h.getUrg())) f |= 0x20;
        return f;
    }

    // ==========================================
    // helper to convert to DTO
    // ==========================================

    private static AlertDto toDto(AlertEvent e) {
        return new AlertDto(
            e.getAlertId(), e.getDetectorName(), e.getSeverity(), e.getAlertType(),
            e.getSourceIP(), e.getSourcePort(), e.getDestinationIP(), e.getDestinationPort(),
            e.getProtocol(), e.getMessage(), e.getTimestamp()
        );
    }
}
