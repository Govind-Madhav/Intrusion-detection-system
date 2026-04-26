package com.ids.config;

import java.util.Objects;

public class CliArgs {

    private final String interfaceName;
    private final int packetCount;
    private final int timeoutMillis;
    private final int snapLen;
    private final boolean verbose;
    private final int threadPoolSize;

    public CliArgs(String interfaceName, int packetCount, int timeoutMillis, int snapLen, boolean verbose, int threadPoolSize) {
        this.interfaceName = interfaceName;
        this.packetCount = validatePacketCount(packetCount);
        this.timeoutMillis = validateTimeout(timeoutMillis);
        this.snapLen = validateSnapLen(snapLen);
        this.verbose = verbose;
        this.threadPoolSize = validateThreadPoolSize(threadPoolSize);
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

    public boolean isVerbose() {
        return verbose;
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    private static int validatePacketCount(int count) {
        if (count <= 0) {
            throw new IllegalArgumentException("Packet count must be greater than zero, got: " + count);
        }
        if (count > 100000) {
            throw new IllegalArgumentException("Packet count must not exceed 100000, got: " + count);
        }
        return count;
    }

    private static int validateTimeout(int timeout) {
        if (timeout <= 0) {
            throw new IllegalArgumentException("Timeout must be greater than zero, got: " + timeout);
        }
        if (timeout > 300000) { // 5 minutes max
            throw new IllegalArgumentException("Timeout must not exceed 300000ms, got: " + timeout);
        }
        return timeout;
    }

    private static int validateSnapLen(int snapLen) {
        if (snapLen < 64 || snapLen > 262144) {
            throw new IllegalArgumentException("SnapLen must be between 64 and 262144, got: " + snapLen);
        }
        return snapLen;
    }

    private static int validateThreadPoolSize(int size) {
        if (size < 1 || size > 32) {
            throw new IllegalArgumentException("Thread pool size must be between 1 and 32, got: " + size);
        }
        return size;
    }

    public static CliArgs parse(String[] args) {
        String interfaceName = null;
        int packetCount = 20;
        int timeoutMillis = 10000;
        int snapLen = 65536;
        boolean verbose = false;
        int threadPoolSize = Math.max(1, Runtime.getRuntime().availableProcessors() / 2);

        for (String arg : args) {
            if (arg.startsWith("--interface=")) {
                interfaceName = arg.substring(arg.indexOf('=') + 1).trim();
                if (interfaceName.isBlank()) {
                    throw new IllegalArgumentException("Interface name cannot be empty");
                }
            } else if (arg.startsWith("--count=")) {
                packetCount = parseIntArg(arg, "count");
            } else if (arg.startsWith("--timeout=")) {
                timeoutMillis = parseIntArg(arg, "timeout");
            } else if (arg.startsWith("--snaplen=")) {
                snapLen = parseIntArg(arg, "snaplen");
            } else if (arg.startsWith("--threads=")) {
                threadPoolSize = parseIntArg(arg, "threads");
            } else if ("-v".equals(arg) || "--verbose".equals(arg)) {
                verbose = true;
            } else if ("-h".equals(arg) || "--help".equals(arg)) {
                printHelpAndExit();
            } else {
                System.err.println("Unknown argument: " + arg);
                printHelpAndExit();
            }
        }

        return new CliArgs(interfaceName, packetCount, timeoutMillis, snapLen, verbose, threadPoolSize);
    }

    private static int parseIntArg(String arg, String name) {
        try {
            return Integer.parseInt(arg.substring(arg.indexOf('=') + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + name + " value: " + arg);
        }
    }

    private static void printHelpAndExit() {
        System.out.println("Usage: java -jar intrusion-detection-system.jar [options]");
        System.out.println("Options:");
        System.out.println("  --interface=<name>   Network interface to capture packets from");
        System.out.println("  --count=<number>     Number of packets to capture (default 20, max 100000)");
        System.out.println("  --timeout=<ms>       Capture timeout in milliseconds (default 10000, max 300000)");
        System.out.println("  --snaplen=<bytes>    Snapshot length for packet capture (default 65536, range 64-262144)");
        System.out.println("  --threads=<number>   Thread pool size (default auto, range 1-32)");
        System.out.println("  -v, --verbose        Enable verbose logging");
        System.out.println("  -h, --help            Show this help message");
        System.exit(0);
    }

    @Override
    public String toString() {
        return "CliArgs{" +
                "interfaceName='" + interfaceName + '\'' +
                ", packetCount=" + packetCount +
                ", timeoutMillis=" + timeoutMillis +
                ", snapLen=" + snapLen +
                ", verbose=" + verbose +
                ", threadPoolSize=" + threadPoolSize +
                '}';
    }
}
