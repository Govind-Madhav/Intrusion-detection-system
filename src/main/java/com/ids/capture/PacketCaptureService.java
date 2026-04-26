package com.ids.capture;

import com.ids.model.PacketData;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.TimeoutException;
import org.pcap4j.core.PcapHandle.PromiscuousMode;
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

public class PacketCaptureService {

    private final int snapLen;
    private final int timeoutMillis;

    public PacketCaptureService(int snapLen, int timeoutMillis) {
        this.snapLen = snapLen;
        this.timeoutMillis = timeoutMillis;
    }

    public List<PacketData> capture(PcapNetworkInterface networkInterface, int packetCount) throws PcapNativeException, NotOpenException {
        if (networkInterface == null) {
            throw new IllegalArgumentException("PcapNetworkInterface must not be null.");
        }
        if (packetCount <= 0) {
            throw new IllegalArgumentException("packetCount must be greater than zero.");
        }

        PcapHandle handle = networkInterface.openLive(snapLen, PromiscuousMode.PROMISCUOUS, timeoutMillis);
        List<PacketData> packets = Collections.synchronizedList(new ArrayList<>());

        try {
            int captured = 0;
            while (captured < packetCount) {
                try {
                    PcapPacket packet = handle.getNextPacketEx();
                    if (packet != null) {
                        packets.add(convert(packet));
                        captured++;
                    }
                } catch (TimeoutException e) {
                    break;
                }
            }
        } finally {
            handle.close();
        }

        return new ArrayList<>(packets);
    }

    private PacketData convert(PcapPacket packet) {
        String sourceIP = "";
        String destinationIP = "";
        String protocol = "Unknown";
        int sourcePort = 0;
        int destinationPort = 0;
        int tcpFlags = 0;
        String interfaceName = packet.getHeader().toString();
        String macSource = "";
        String macDestination = "";
        String packetType = "Unknown";
        boolean isMalformed = false;

        try {
            EthernetPacket ethernet = packet.get(EthernetPacket.class);
            if (ethernet != null) {
                macSource = ethernet.getHeader().getSrcAddr().toString();
                macDestination = ethernet.getHeader().getDstAddr().toString();
                packetType = "Ethernet";
            }

            IpV4Packet ipv4 = packet.get(IpV4Packet.class);
            IpV6Packet ipv6 = packet.get(IpV6Packet.class);
            ArpPacket arp = packet.get(ArpPacket.class);
            TcpPacket tcp = packet.get(TcpPacket.class);
            UdpPacket udp = packet.get(UdpPacket.class);
            IcmpV4CommonPacket icmpv4 = packet.get(IcmpV4CommonPacket.class);
            IcmpV6CommonPacket icmpv6 = packet.get(IcmpV6CommonPacket.class);

            if (ipv4 != null) {
                sourceIP = ipv4.getHeader().getSrcAddr().getHostAddress();
                destinationIP = ipv4.getHeader().getDstAddr().getHostAddress();
                packetType = "IPv4";
            } else if (ipv6 != null) {
                sourceIP = ipv6.getHeader().getSrcAddr().getHostAddress();
                destinationIP = ipv6.getHeader().getDstAddr().getHostAddress();
                packetType = "IPv6";
            } else if (arp != null) {
                packetType = "ARP";
            }

            if (tcp != null) {
                protocol = "TCP";
                sourcePort = tcp.getHeader().getSrcPort().valueAsInt();
                destinationPort = tcp.getHeader().getDstPort().valueAsInt();
                tcpFlags = tcp.getHeader().getRawValue();
            } else if (udp != null) {
                protocol = "UDP";
                sourcePort = udp.getHeader().getSrcPort().valueAsInt();
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

        Packet payloadPacket = packet.getPayload();
        byte[] payload = payloadPacket != null ? payloadPacket.getRawData() : new byte[0];

        return new PacketData(
                sourceIP,
                destinationIP,
                protocol,
                sourcePort,
                destinationPort,
                packet.length(),
                packet.getTimestamp().getTime(),
                payload,
                tcpFlags,
                interfaceName,
                macSource,
                macDestination,
                packetType,
                isMalformed
        );
    }
}
