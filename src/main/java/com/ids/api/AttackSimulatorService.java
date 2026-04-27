package com.ids.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * this class makes fake attacks so we can test the UI without actually attacking the network
 * it sends alerts to db and websocket
 * i used ScheduledExecutorService to make them delay a bit so it looks real
 */
@Service
public class AttackSimulatorService {

    private static final Logger log = LoggerFactory.getLogger(AttackSimulatorService.class);

    private final AlertStore alertStore;
    private final SimpMessagingTemplate messaging;
    private final Random random = new Random();

    // thread pool to delay the attacks so they dont all fire at once
    private final ScheduledExecutorService scheduler =
            Executors.newScheduledThreadPool(4);

    // some random ips to use as attackers
    private static final String[] ATTACKER_IPS = {
        "203.0.113.10", "198.51.100.42", "192.0.2.77",
        "185.220.101.5", "91.108.4.200", "45.33.32.156",
        "104.21.45.89",  "162.243.170.4"
    };
    private static final String[] TARGET_IPS = {
        "10.0.0.1", "192.168.1.100", "172.16.0.5", "10.10.0.50"
    };

    public AttackSimulatorService(AlertStore alertStore, SimpMessagingTemplate messaging) {
        this.alertStore = alertStore;
        this.messaging  = messaging;
    }

    // =======================================================
    // Attack 1: DDOS (ping flood)
    // =======================================================
    public int simulateDdos() {
        String target = TARGET_IPS[random.nextInt(TARGET_IPS.length)];
        int total = 0;

        // loop 5 times to simulate 5 different computers attacking
        for (int i = 0; i < 5; i++) {
            final String attacker = ATTACKER_IPS[i];
            final int packetCount = 120 + random.nextInt(100); // 120–220 packets
            final int delayMs = i * 300; // wait a bit so they dont all hit at exact same millisecond

            scheduler.schedule(() -> {
                String severity = packetCount > 150 ? "CRITICAL" : "HIGH";
                String message = String.format(
                    "%d ICMP packets from %s to %s in 5s window — DDoS simulation",
                    packetCount, attacker, target);
                inject("ICMP_FLOOD_DETECTOR", severity, "ICMP_FLOOD",
                       attacker, target, 0, 0, "ICMPv4", message);
            }, delayMs, TimeUnit.MILLISECONDS);
            total++;
        }

        log.info("[SIM] DDoS scenario started → 5 attackers targeting {}", target);
        return total;
    }

    // =======================================================
    // Attack 2: SYN Port Scan (checking open ports)
    // =======================================================
    public int simulatePortScan() {
        String attacker = ATTACKER_IPS[random.nextInt(ATTACKER_IPS.length)];
        String target   = TARGET_IPS[random.nextInt(TARGET_IPS.length)];
        int[]  ports    = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5432, 8080};
        int total = 0;

        // first trigger the main scan alert
        scheduler.schedule(() -> {
            String msg = String.format("SYN port scan from %s — swept %d ports on %s", attacker, ports.length, target);
            inject("SYN_SCAN_DETECTOR", "HIGH", "SYN_SCAN",
                   attacker, target, randomEphemeralPort(), 0, "TCP", msg);
        }, 0, TimeUnit.MILLISECONDS);
        total++;

        // then simulate hitting some important ports during the scan
        List<int[]> riskyHits = List.of(
            new int[]{445, 3389}, new int[]{3306, 22}, new int[]{5432, 23}
        );
        for (int i = 0; i < riskyHits.size(); i++) {
            final int[] hit = riskyHits.get(i);
            final int delay = 200 + i * 150;
            scheduler.schedule(() -> {
                for (int port : hit) {
                    String svc = portName(port);
                    inject("RISKY_PORT_DETECTOR", "HIGH", "RISKY_PORT_ACCESS",
                           attacker, target, randomEphemeralPort(), port, "TCP",
                           String.format("Port scan hit %s port %d (%s) on %s", attacker, port, svc, target));
                }
            }, delay, TimeUnit.MILLISECONDS);
            total += hit.length;
        }

        log.info("[SIM] Port scan scenario → {} targeting {}", attacker, target);
        return total;
    }

    // =======================================================
    // Attack 3: Xmas / Stealth Scan combo
    // =======================================================
    public int simulateXmasScan() {
        String attacker = ATTACKER_IPS[random.nextInt(ATTACKER_IPS.length)];
        String target   = TARGET_IPS[random.nextInt(TARGET_IPS.length)];
        int total = 0;

        String[][] scans = {
            {"XMAS_SCAN", "Xmas scan (FIN+PSH+URG) from " + attacker},
            {"NULL_SCAN",  "Null scan (no flags) from " + attacker},
            {"FIN_SCAN",   "FIN scan from " + attacker},
        };

        for (int i = 0; i < scans.length; i++) {
            final String[] scan = scans[i];
            final int delay = i * 400;
            scheduler.schedule(() ->
                inject("SYN_SCAN_DETECTOR", "HIGH", scan[0],
                       attacker, target, randomEphemeralPort(),
                       80 + random.nextInt(400), "TCP", scan[1]),
                delay, TimeUnit.MILLISECONDS
            );
            total++;
        }

        log.info("[SIM] Xmas/Stealth scan combo from {}", attacker);
        return total;
    }

    // =======================================================
    // Attack 4: Database Breach (trying to hack databases)
    // =======================================================
    public int simulateDbBreach() {
        String attacker = ATTACKER_IPS[random.nextInt(ATTACKER_IPS.length)];
        String target   = TARGET_IPS[random.nextInt(TARGET_IPS.length)];

        int[][] dbPorts = {
            {3306, 0},  // MySQL   → CRITICAL
            {5432, 0},  // Postgres→ CRITICAL
            {27017,0},  // MongoDB → CRITICAL
            {1433, 0},  // MSSQL   → CRITICAL
            {6379, 0},  // Redis   → HIGH
            {9200, 0},  // Elastic → HIGH
        };

        for (int i = 0; i < dbPorts.length; i++) {
            final int port = dbPorts[i][0];
            final int delay = i * 250;
            scheduler.schedule(() -> {
                String svc  = portName(port);
                String sev  = (port == 6379 || port == 9200) ? "HIGH" : "CRITICAL";
                String msg  = String.format(
                    "CRITICAL: %s attempting unauthorised access to %s (port %d) on %s — DB breach simulation",
                    attacker, svc, port, target);
                inject("RISKY_PORT_DETECTOR", sev, "RISKY_PORT_ACCESS",
                       attacker, target, randomEphemeralPort(), port, "TCP", msg);
            }, delay, TimeUnit.MILLISECONDS);
        }

        log.info("[SIM] DB breach scenario → {} hitting all DB ports on {}", attacker, target);
        return dbPorts.length;
    }

    // =======================================================
    // Attack 5: Brute Force (guessing passwords)
    // =======================================================
    public int simulateBruteForce() {
        String attacker = ATTACKER_IPS[random.nextInt(ATTACKER_IPS.length)];
        String target   = TARGET_IPS[random.nextInt(TARGET_IPS.length)];
        int attempts = 12;

        for (int i = 0; i < attempts; i++) {
            final int attempt = i + 1;
            final boolean rdp  = random.nextBoolean();
            final int port     = rdp ? 3389 : 22;
            final String svc   = rdp ? "RDP" : "SSH";
            final int delay    = i * 350;

            scheduler.schedule(() -> {
                String msg = String.format(
                    "Brute-force attempt #%d: %s → %s:%d (%s) — repeated auth failure",
                    attempt, attacker, target, port, svc);
                inject("RISKY_PORT_DETECTOR", "CRITICAL", "RISKY_PORT_ACCESS",
                       attacker, target, randomEphemeralPort(), port, "TCP", msg);
            }, delay, TimeUnit.MILLISECONDS);
        }

        log.info("[SIM] Brute force → {} making {} attempts on {}", attacker, attempts, target);
        return attempts;
    }

    // =======================================================
    // Attack 6: Do everything at once
    // =======================================================
    public int simulateCoordinated() {
        log.info("[SIM] Coordinated attack — launching all scenarios simultaneously");
        int total = 0;
        total += simulateDdos();
        total += simulatePortScan();
        total += simulateXmasScan();
        total += simulateDbBreach();
        total += simulateBruteForce();
        return total;
    }

    // =======================================================
    // helper functions down here
    // =======================================================
    private void inject(String detector, String severity, String alertType,
                        String srcIp, String dstIp, int srcPort, int dstPort,
                        String protocol, String message) {
        AlertDto alert = new AlertDto(
            "SIM-" + UUID.randomUUID().toString().substring(0, 8),
            detector, severity, alertType,
            srcIp, srcPort, dstIp, dstPort,
            protocol, message,
            System.currentTimeMillis()
        );
        alertStore.add(alert);
        messaging.convertAndSend("/topic/alerts", alert);
    }

    private int randomEphemeralPort() {
        return 1024 + random.nextInt(60000);
    }

    private static String portName(int port) {
        return switch (port) {
            case 22   -> "SSH";
            case 23   -> "Telnet";
            case 3389 -> "RDP";
            case 445  -> "SMB";
            case 3306 -> "MySQL";
            case 5432 -> "PostgreSQL";
            case 27017-> "MongoDB";
            case 1433 -> "MSSQL";
            case 6379 -> "Redis";
            case 9200 -> "Elasticsearch";
            default   -> "Port-" + port;
        };
    }
}
