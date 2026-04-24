package com.ids;

import java.io.EOFException;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public final class Main {

  private static final Logger LOGGER = Logger.getLogger("ids");

  private Main() {
  }

  public static void main(String[] args) {
    AppArgs appArgs = AppArgs.parse(args);
    if (appArgs.help()) {
      AppArgs.printHelp();
      return;
    }

    configureLogger(appArgs.logFile());

    IDSSettings settings = new IDSSettings(
        appArgs.windowSeconds(),
        appArgs.synThreshold(),
        appArgs.icmpThreshold());

    IDSDetector detector = new IDSDetector(settings, LOGGER);
    AtomicBoolean running = new AtomicBoolean(true);

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      running.set(false);
      LOGGER.info("Shutdown requested. Stopping IDS...");
    }));

    try {
      PcapNetworkInterface nif = chooseInterface(appArgs.iface());
      if (nif == null) {
        LOGGER.severe("No network interface found. Ensure Npcap is installed and run as Administrator.");
        return;
      }

      LOGGER.info("Using interface: " + nif.getName() + " (" + nif.getDescription() + ")");
      runCaptureLoop(nif, detector, running);
    } catch (PcapNativeException e) {
      LOGGER.log(Level.SEVERE, "Failed to initialize packet capture", e);
    }
  }

  private static PcapNetworkInterface chooseInterface(String ifaceHint) throws PcapNativeException {
    List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
    if (interfaces == null || interfaces.isEmpty()) {
      return null;
    }

    if (ifaceHint == null || ifaceHint.isBlank()) {
      return interfaces.get(0);
    }

    String needle = ifaceHint.toLowerCase();
    for (PcapNetworkInterface nif : interfaces) {
      String name = nif.getName() == null ? "" : nif.getName().toLowerCase();
      String description = nif.getDescription() == null ? "" : nif.getDescription().toLowerCase();
      if (name.contains(needle) || description.contains(needle)) {
        return nif;
      }
    }

    LOGGER.warning("Interface hint not matched. Falling back to first available interface.");
    return interfaces.get(0);
  }

  private static void runCaptureLoop(PcapNetworkInterface nif, IDSDetector detector, AtomicBoolean running)
      throws PcapNativeException {
    int snapLen = 65536;
    int timeoutMillis = 10;

    try (PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeoutMillis)) {
      LOGGER.info("IDS started. Press Ctrl+C to stop.");
      while (running.get()) {
        try {
          Packet packet = handle.getNextPacketEx();
          detector.processPacket(packet);
        } catch (EOFException ignored) {
          // End-of-file can occur on some capture backends; continue polling.
        } catch (TimeoutException ignored) {
          // Timeout is expected while polling for packets.
        } catch (NotOpenException e) {
          LOGGER.log(Level.SEVERE, "Capture handle closed unexpectedly", e);
          break;
        }
      }
      LOGGER.info("IDS stopped.");
    }
  }

  private static void configureLogger(String logFilePath) {
    LOGGER.setUseParentHandlers(false);
    LOGGER.setLevel(Level.INFO);

    Formatter formatter = new Formatter() {
      @Override
      public String format(LogRecord record) {
        return String.format("%1$tF %1$tT [%2$s] %3$s%n",
            record.getMillis(),
            record.getLevel().getName(),
            record.getMessage());
      }
    };

    ConsoleHandler console = new ConsoleHandler();
    console.setLevel(Level.INFO);
    console.setFormatter(formatter);

    LOGGER.getHandlers();
    for (var handler : LOGGER.getHandlers()) {
      LOGGER.removeHandler(handler);
    }

    LOGGER.addHandler(console);

    try {
      FileHandler file = new FileHandler(logFilePath, true);
      file.setLevel(Level.INFO);
      file.setFormatter(formatter);
      LOGGER.addHandler(file);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Unable to write to log file: " + logFilePath, e);
    }
  }

  private record AppArgs(
      String iface,
      int windowSeconds,
      int synThreshold,
      int icmpThreshold,
      String logFile,
      boolean help) {

    static AppArgs parse(String[] args) {
      String iface = null;
      int window = 10;
      int syn = 15;
      int icmp = 50;
      String log = "alerts.log";
      boolean help = false;

      List<String> all = new ArrayList<>();
      for (String arg : args) {
        all.add(arg);
      }

      for (int i = 0; i < all.size(); i++) {
        String arg = all.get(i);
        switch (arg) {
          case "--help", "-h" -> help = true;
          case "--iface" -> iface = readValue(all, ++i, "--iface");
          case "--window" -> window = Integer.parseInt(readValue(all, ++i, "--window"));
          case "--syn-threshold" -> syn = Integer.parseInt(readValue(all, ++i, "--syn-threshold"));
          case "--icmp-threshold" -> icmp = Integer.parseInt(readValue(all, ++i, "--icmp-threshold"));
          case "--log-file" -> log = readValue(all, ++i, "--log-file");
          default -> {
            if (arg.startsWith("--")) {
              throw new IllegalArgumentException("Unknown argument: " + arg);
            }
          }
        }
      }

      return new AppArgs(iface, window, syn, icmp, log, help);
    }

    private static String readValue(List<String> args, int idx, String key) {
      if (idx >= args.size()) {
        throw new IllegalArgumentException("Missing value for " + key);
      }
      return args.get(idx);
    }

    static void printHelp() {
      System.out.println("Usage: mvn exec:java -Dexec.args=\"[options]\"");
      System.out.println("Options:");
      System.out.println("  --iface <name>            Interface name/description hint");
      System.out.println("  --window <seconds>        Detection window (default 10)");
      System.out.println("  --syn-threshold <count>   Unique destination ports threshold (default 15)");
      System.out.println("  --icmp-threshold <count>  ICMP packet threshold (default 50)");
      System.out.println("  --log-file <path>         Alert log file (default alerts.log)");
      System.out.println("  --help                    Show help");
    }
  }

  private record IDSSettings(
      int windowSeconds,
      int synThreshold,
      int icmpThreshold) {
  }

  private static final class IDSDetector {

    private static final Map<Integer, String> RISKY_PORTS = Map.of(
        21, "FTP",
        23, "Telnet",
        445, "SMB",
        3389, "RDP");

    private final IDSSettings settings;
    private final Logger logger;

    private final Map<String, Deque<SynEvent>> synEventsBySource = new HashMap<>();
    private final Map<String, Set<Integer>> uniqueSynPortsBySource = new HashMap<>();
    private final Map<String, Deque<Long>> icmpEventsBySource = new HashMap<>();

    private IDSDetector(IDSSettings settings, Logger logger) {
      this.settings = settings;
      this.logger = logger;
    }

    private void processPacket(Packet packet) {
      IpV4Packet ipV4 = packet.get(IpV4Packet.class);
      if (ipV4 == null) {
        return;
      }

      String srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
      String dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
      long now = Instant.now().getEpochSecond();

      TcpPacket tcp = packet.get(TcpPacket.class);
      if (tcp != null) {
        int dstPort = tcp.getHeader().getDstPort().valueAsInt();
        boolean isSyn = tcp.getHeader().getSyn();
        boolean isAck = tcp.getHeader().getAck();

        if (isSyn && !isAck) {
          trackSyn(srcIp, dstPort, now);
          checkSynScan(srcIp, dstIp);
        }

        checkRiskyPort(srcIp, dstIp, dstPort);
      }

      IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
      if (icmp != null) {
        trackIcmp(srcIp, now);
        checkIcmpFlood(srcIp, dstIp);
      }
    }

    private void trackSyn(String srcIp, int dstPort, long now) {
      Deque<SynEvent> events = synEventsBySource.computeIfAbsent(srcIp, ignored -> new ArrayDeque<>());
      Set<Integer> uniquePorts = uniqueSynPortsBySource.computeIfAbsent(srcIp, ignored -> new HashSet<>());

      events.addLast(new SynEvent(now, dstPort));
      uniquePorts.add(dstPort);
      evictOldSyn(srcIp, now);
    }

    private void evictOldSyn(String srcIp, long now) {
      Deque<SynEvent> events = synEventsBySource.get(srcIp);
      Set<Integer> uniquePorts = uniqueSynPortsBySource.get(srcIp);
      if (events == null || uniquePorts == null) {
        return;
      }

      long window = settings.windowSeconds();
      while (!events.isEmpty() && now - events.peekFirst().ts() > window) {
        SynEvent old = events.removeFirst();
        boolean stillExists = events.stream().anyMatch(ev -> ev.dstPort() == old.dstPort());
        if (!stillExists) {
          uniquePorts.remove(old.dstPort());
        }
      }
    }

    private void checkSynScan(String srcIp, String dstIp) {
      Set<Integer> ports = uniqueSynPortsBySource.getOrDefault(srcIp, Set.of());
      int count = ports.size();

      if (count >= settings.synThreshold()) {
        logger.warning(() -> String.format(
            "ALERT: Possible SYN scan from %s against %s (%d unique ports in %ds)",
            srcIp,
            dstIp,
            count,
            settings.windowSeconds()));

        synEventsBySource.remove(srcIp);
        uniqueSynPortsBySource.remove(srcIp);
      }
    }

    private void trackIcmp(String srcIp, long now) {
      Deque<Long> events = icmpEventsBySource.computeIfAbsent(srcIp, ignored -> new ArrayDeque<>());
      events.addLast(now);

      long window = settings.windowSeconds();
      while (!events.isEmpty() && now - events.peekFirst() > window) {
        events.removeFirst();
      }
    }

    private void checkIcmpFlood(String srcIp, String dstIp) {
      Deque<Long> events = icmpEventsBySource.getOrDefault(srcIp, new ArrayDeque<>());
      int count = events.size();

      if (count >= settings.icmpThreshold()) {
        logger.warning(() -> String.format(
            "ALERT: Possible ICMP flood from %s to %s (%d packets in %ds)",
            srcIp,
            dstIp,
            count,
            settings.windowSeconds()));
        icmpEventsBySource.remove(srcIp);
      }
    }

    private void checkRiskyPort(String srcIp, String dstIp, int dstPort) {
      if (!RISKY_PORTS.containsKey(dstPort)) {
        return;
      }

      logger.warning(() -> String.format(
          "ALERT: Connection attempt from %s to %s on risky port %d (%s)",
          srcIp,
          dstIp,
          dstPort,
          RISKY_PORTS.get(dstPort)));
    }

    private record SynEvent(long ts, int dstPort) {
    }
  }
}
