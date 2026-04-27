package com.ids.capture;

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Captures raw packets from a network interface using pcap4j 1.8.2.
 *
 * Key API fixes vs the original code:
 *  - PcapPacket does not exist in 1.8.2 — use org.pcap4j.packet.Packet
 *  - TimeoutException does not exist in 1.8.2 — getNextPacket() returns null on timeout
 *  - PromiscuousMode lives on PcapNetworkInterface, not PcapHandle
 *  - TCP flags are extracted via individual flag getters, not getRawValue()
 */
public class PacketCaptureService implements AutoCloseable {

    private final int snapLen;
    private final int timeoutMillis;
    private volatile boolean capturing = false;
    private final AtomicInteger packetsProcessed = new AtomicInteger(0);
    private final AtomicInteger packetsFailed    = new AtomicInteger(0);

    public PacketCaptureService(int snapLen, int timeoutMillis) {
        this.snapLen      = Math.max(64, Math.min(snapLen, 262144));
        this.timeoutMillis = Math.max(1, timeoutMillis);
    }

    public List<PacketData> capture(PcapNetworkInterface networkInterface, int packetCount)
            throws PcapNativeException, NotOpenException {

        if (networkInterface == null) {
            throw new IllegalArgumentException("PcapNetworkInterface must not be null.");
        }
        if (packetCount <= 0) {
            throw new IllegalArgumentException("packetCount must be greater than zero.");
        }

        packetsProcessed.set(0);
        packetsFailed.set(0);
        capturing = true;

        PcapHandle handle = null;
        List<PacketData> packets = Collections.synchronizedList(new ArrayList<>(packetCount));

        try {
            // Fixed: PromiscuousMode is on PcapNetworkInterface in pcap4j 1.8.2
            handle = networkInterface.openLive(snapLen, PromiscuousMode.PROMISCUOUS, timeoutMillis);

            int captured = 0;
            while (captured < packetCount && capturing) {
                // Fixed: getNextPacket() returns null on timeout — no TimeoutException in 1.8.2
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    try {
                        PacketData packetData = convert(packet);
                        packets.add(packetData);
                        packetsProcessed.incrementAndGet();
                        captured++;
                    } catch (Exception e) {
                        packetsFailed.incrementAndGet();
                    }
                } else {
                    // null = timeout, yield and retry
                    Thread.yield();
                }
            }
        } finally {
            capturing = false;
            if (handle != null) {
                try { handle.close(); } catch (Exception ignored) {}
            }
        }

        return new ArrayList<>(packets);
    }

    public void stopCapture() {
        capturing = false;
    }

    public int getPacketsProcessed() { return packetsProcessed.get(); }
    public int getPacketsFailed()    { return packetsFailed.get(); }

    public CaptureStatistics getStatistics() {
        return new CaptureStatistics(packetsProcessed.get(), packetsFailed.get());
    }

    private PacketData convert(Packet packet) {
        Objects.requireNonNull(packet, "Packet must not be null");

        String sourceIP       = "";
        String destinationIP  = "";
        String protocol       = "Unknown";
        int    sourcePort     = 0;
        int    destinationPort = 0;
        int    tcpFlags       = 0;
        String interfaceName  = "";
        String macSource      = "";
        String macDestination = "";
        String packetType     = "Unknown";
        boolean isMalformed   = false;

        try {
            // Ethernet layer
            EthernetPacket ethernet = packet.get(EthernetPacket.class);
            if (ethernet != null) {
                macSource      = safeString(ethernet.getHeader().getSrcAddr());
                macDestination = safeString(ethernet.getHeader().getDstAddr());
                packetType     = "Ethernet";
            }

            // IP layer
            IpV4Packet ipv4 = packet.get(IpV4Packet.class);
            IpV6Packet ipv6 = packet.get(IpV6Packet.class);

            if (ipv4 != null) {
                sourceIP      = safeString(ipv4.getHeader().getSrcAddr());
                destinationIP = safeString(ipv4.getHeader().getDstAddr());
                packetType    = "IPv4";
            } else if (ipv6 != null) {
                sourceIP      = safeString(ipv6.getHeader().getSrcAddr());
                destinationIP = safeString(ipv6.getHeader().getDstAddr());
                packetType    = "IPv6";
            } else {
                ArpPacket arp = packet.get(ArpPacket.class);
                if (arp != null) packetType = "ARP";
            }

            // Transport layer
            TcpPacket         tcp    = packet.get(TcpPacket.class);
            UdpPacket         udp    = packet.get(UdpPacket.class);
            IcmpV4CommonPacket icmpv4 = packet.get(IcmpV4CommonPacket.class);
            IcmpV6CommonPacket icmpv6 = packet.get(IcmpV6CommonPacket.class);

            if (tcp != null) {
                protocol       = "TCP";
                sourcePort     = tcp.getHeader().getSrcPort().valueAsInt();
                destinationPort = tcp.getHeader().getDstPort().valueAsInt();
                // Fixed: getRawValue() doesn't exist in 1.8.2 — reconstruct flags byte manually
                tcpFlags = buildTcpFlags(tcp.getHeader());
            } else if (udp != null) {
                protocol       = "UDP";
                sourcePort     = udp.getHeader().getSrcPort().valueAsInt();
                destinationPort = udp.getHeader().getDstPort().valueAsInt();
            } else if (icmpv4 != null) {
                protocol = "ICMPv4";
            } else if (icmpv6 != null) {
                protocol = "ICMPv6";
            } else if (ipv4 != null) {
                protocol = ipv4.getHeader().getProtocol().name();
            } else if (ipv6 != null) {
                protocol = ipv6.getHeader().getNextHeader().name();
            }

        } catch (Exception e) {
            isMalformed = true;
        }

        byte[] payload = extractPayload(packet);

        return new PacketData(
                sourceIP, destinationIP, protocol,
                sourcePort, destinationPort,
                packet.length(),
                System.currentTimeMillis(),   // pcap4j 1.8.2 Packet has no getTimestamp()
                payload, tcpFlags,
                interfaceName, macSource, macDestination,
                packetType, isMalformed
        );
    }

    /**
     * Reconstruct the TCP flags byte from individual boolean getters.
     * pcap4j 1.8.2 TcpHeader has no getRawValue() — each flag is a separate getter.
     */
    private int buildTcpFlags(TcpPacket.TcpHeader h) {
        int flags = 0;
        if (Boolean.TRUE.equals(h.getFin())) flags |= 0x01;
        if (Boolean.TRUE.equals(h.getSyn())) flags |= 0x02;
        if (Boolean.TRUE.equals(h.getRst())) flags |= 0x04;
        if (Boolean.TRUE.equals(h.getPsh())) flags |= 0x08;
        if (Boolean.TRUE.equals(h.getAck())) flags |= 0x10;
        if (Boolean.TRUE.equals(h.getUrg())) flags |= 0x20;
        return flags;
    }

    private String safeString(Object obj) {
        return obj != null ? obj.toString() : "";
    }

    private byte[] extractPayload(Packet packet) {
        try {
            Packet payload = packet.getPayload();
            return payload != null ? payload.getRawData() : new byte[0];
        } catch (Exception e) {
            return new byte[0];
        }
    }

    @Override
    public void close() {
        stopCapture();
    }

    public static class CaptureStatistics {
        public final int processed;
        public final int failed;

        public CaptureStatistics(int processed, int failed) {
            this.processed = processed;
            this.failed    = failed;
        }

        @Override
        public String toString() {
            return String.format("CaptureStatistics{processed=%d, failed=%d}", processed, failed);
        }
    }
}
