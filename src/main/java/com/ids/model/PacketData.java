package com.ids.model;

public class PacketData {
	private String sourceIP;
	private String destinationIP;
	private String protocol;
	private int sourcePort;
	private int destinationPort;
	private int packetSize;
	private long timestamp;
    private byte[] payload;
	private int tcpFlags;             // TCP flags (SYN, ACK, etc.)
	private String interfaceName;
	private String macSource;
	private String macDestination;
	private String packetType;        // IPv4, IPv6, ARP, etc.
	private boolean isMalformed;

	public PacketData() {}

	public PacketData(String sourceIP, String destinationIP, String protocol, int sourcePort, int destinationPort, int packetSize, long timestamp, byte[] payload, int tcpFlags, String interfaceName, String macSource, String macDestination, String packetType, boolean isMalformed) {
		this.sourceIP = sourceIP;
		this.destinationIP = destinationIP;
		this.protocol = protocol;
		this.sourcePort = sourcePort;
		this.destinationPort = destinationPort;
		this.packetSize = packetSize;
		this.timestamp = timestamp;
		this.payload = payload;
		this.tcpFlags = tcpFlags;
		this.interfaceName = interfaceName;
		this.macSource = macSource;
		this.macDestination = macDestination;
		this.packetType = packetType;
		this.isMalformed = isMalformed;
	}

	public String getSourceIP() { return sourceIP; }
	public void setSourceIP(String sourceIP) { this.sourceIP = sourceIP; }
	public String getDestinationIP() { return destinationIP; }
	public void setDestinationIP(String destinationIP) { this.destinationIP = destinationIP; }
	public String getProtocol() { return protocol; }
	public void setProtocol(String protocol) { this.protocol = protocol; }
	public int getSourcePort() { return sourcePort; }
	public void setSourcePort(int sourcePort) { this.sourcePort = sourcePort; }
	public int getDestinationPort() { return destinationPort; }
	public void setDestinationPort(int destinationPort) { this.destinationPort = destinationPort; }
	public int getPacketSize() { return packetSize; }
	public void setPacketSize(int packetSize) { this.packetSize = packetSize; }
	public long getTimestamp() { return timestamp; }
	public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
	public byte[] getPayload() { return payload; }
	public void setPayload(byte[] payload) { this.payload = payload; }
	public int getTcpFlags() { return tcpFlags; }
	public void setTcpFlags(int tcpFlags) { this.tcpFlags = tcpFlags; }
	public String getInterfaceName() { return interfaceName; }
	public void setInterfaceName(String interfaceName) { this.interfaceName = interfaceName; }
	public String getMacSource() { return macSource; }
	public void setMacSource(String macSource) { this.macSource = macSource; }
	public String getMacDestination() { return macDestination; }
	public void setMacDestination(String macDestination) { this.macDestination = macDestination; }
	public String getPacketType() { return packetType; }
	public void setPacketType(String packetType) { this.packetType = packetType; }
	public boolean isMalformed() { return isMalformed; }
	public void setMalformed(boolean malformed) { isMalformed = malformed; }

	@Override
	public String toString() {
		return "PacketData{" +
				"sourceIP='" + sourceIP + '\'' +
				", destinationIP='" + destinationIP + '\'' +
				", protocol='" + protocol + '\'' +
				", sourcePort=" + sourcePort +
				", destinationPort=" + destinationPort +
				", packetSize=" + packetSize +
				", timestamp=" + timestamp +
				", tcpFlags=" + tcpFlags +
				", interfaceName='" + interfaceName + '\'' +
				", macSource='" + macSource + '\'' +
				", macDestination='" + macDestination + '\'' +
				", packetType='" + packetType + '\'' +
				", isMalformed=" + isMalformed +
				'}';
	}
}
