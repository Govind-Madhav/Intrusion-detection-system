package com.ids.config;

public class CliArgs {

    private final String interfaceName;
    private final int packetCount;
    private final int timeoutMillis;
    private final int snapLen;

    public CliArgs(String interfaceName, int packetCount, int timeoutMillis, int snapLen) {
        this.interfaceName = interfaceName;
        this.packetCount = packetCount;
        this.timeoutMillis = timeoutMillis;
        this.snapLen = snapLen;
    }

    public String getInterfaceName() {
        return interfaceName;
    }

    public int getPacketCount() {
        return packetCount;
    }

    public int getTimeoutMillis() {
        return timeoutMillis;
    }

    public int getSnapLen() {
        return snapLen;
    }

    public static CliArgs parse(String[] args) {
        String interfaceName = null;
        int packetCount = 20;
        int timeoutMillis = 10000;
        int snapLen = 65536;

        for (String arg : args) {
            if (arg.startsWith("--interface=")) {
                interfaceName = arg.substring(arg.indexOf('=') + 1);
            } else if (arg.startsWith("--count=")) {
                packetCount = Integer.parseInt(arg.substring(arg.indexOf('=') + 1));
            } else if (arg.startsWith("--timeout=")) {
                timeoutMillis = Integer.parseInt(arg.substring(arg.indexOf('=') + 1));
            } else if (arg.startsWith("--snaplen=")) {
                snapLen = Integer.parseInt(arg.substring(arg.indexOf('=') + 1));
            } else if ("-h".equals(arg) || "--help".equals(arg)) {
                printHelpAndExit();
            }
        }

        return new CliArgs(interfaceName, packetCount, timeoutMillis, snapLen);
    }

    private static void printHelpAndExit() {
        System.out.println("Usage: java -jar intrusion-detection-system.jar [options]");
        System.out.println("Options:");
        System.out.println("  --interface=<name>   Select the network interface to capture packets from");
        System.out.println("  --count=<number>     Number of packets to capture (default 20)");
        System.out.println("  --timeout=<ms>       Capture timeout in milliseconds (default 10000)");
        System.out.println("  --snaplen=<bytes>    Snapshot length for packet capture (default 65536)");
        System.out.println("  -h, --help            Show this help message");
        System.exit(0);
    }
}
