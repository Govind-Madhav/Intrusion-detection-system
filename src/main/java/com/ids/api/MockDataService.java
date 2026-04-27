package com.ids.api;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Generates realistic mock alert data.
 * On startup: seeds 20 historical alerts ONLY if the DB is empty.
 * Every 4 seconds: broadcasts one new alert via WebSocket (simulates live capture).
 */
@Component
public class MockDataService {

    private static final Logger log = LoggerFactory.getLogger(MockDataService.class);

    private static final String[] SOURCE_IPS = {
        "192.168.1.10", "10.0.0.15", "172.16.0.5",
        "192.168.100.25", "10.10.10.8", "203.0.113.42", "198.51.100.7"
    };
    private static final String[] DEST_IPS = {
        "192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1"
    };
    private static final int[]    RISKY_PORTS = {22, 23, 3389, 445, 135, 139, 4444, 6666, 31337};
    private static final int[]    COMMON_PORTS = {80, 443, 22, 23, 3389, 445, 8080, 8443};
    private static final String[] ALERT_TYPES  = {"SYN_SCAN", "ICMP_FLOOD", "RISKY_PORT"};

    @Autowired private AlertStore       alertStore;
    @Autowired private AlertRepository  alertRepository;
    @Autowired private SimpMessagingTemplate messaging;

    private final Random        random  = new Random();
    private final AtomicInteger counter = new AtomicInteger(1000);

    @PostConstruct
    public void seedInitialAlerts() {
        // Only seed when the table is completely empty — never on subsequent restarts
        if (alertRepository.count() > 0) {
            log.info("DB already has {} alert(s) — skipping seed.", alertRepository.count());
            return;
        }
        log.info("Empty DB detected — seeding 20 initial mock alerts.");
        for (int i = 20; i > 0; i--) {
            long ts = System.currentTimeMillis() - (long) i * 25_000L;
            alertStore.add(buildRandomAlert(ts));
        }
    }

    @Scheduled(fixedDelay = 4000)
    public void broadcastLiveAlert() {
        AlertDto alert = buildRandomAlert(System.currentTimeMillis());
        alertStore.add(alert);
        messaging.convertAndSend("/topic/alerts", alert);
    }

    /** Public so AlertController can call it for the /mock endpoint. */
    public AlertDto buildRandomAlert(long timestamp) {
        String type      = ALERT_TYPES[random.nextInt(ALERT_TYPES.length)];
        String srcIp     = SOURCE_IPS[random.nextInt(SOURCE_IPS.length)];
        String dstIp     = DEST_IPS[random.nextInt(DEST_IPS.length)];
        String severity;
        String detector;
        String protocol;
        String message;
        int    srcPort;
        int    dstPort;

        switch (type) {
            case "SYN_SCAN" -> {
                severity = random.nextFloat() < 0.7f ? "HIGH" : "CRITICAL";
                detector = "SynScanDetector";
                srcPort  = 1024 + random.nextInt(60000);
                dstPort  = COMMON_PORTS[random.nextInt(COMMON_PORTS.length)];
                protocol = "TCP";
                message  = "SYN scan detected — " + (15 + random.nextInt(50)) + " SYN pkts in 10 s window from " + srcIp;
            }
            case "ICMP_FLOOD" -> {
                severity = random.nextFloat() < 0.5f ? "MEDIUM" : "HIGH";
                detector = "IcmpFloodDetector";
                srcPort  = 0;
                dstPort  = 0;
                protocol = "ICMP";
                message  = "ICMP flood — " + (50 + random.nextInt(200)) + " pkts/s from " + srcIp;
            }
            default -> {    // RISKY_PORT
                float r  = random.nextFloat();
                severity = r < 0.25f ? "LOW" : r < 0.65f ? "MEDIUM" : "HIGH";
                detector = "RiskyPortDetector";
                srcPort  = 1024 + random.nextInt(60000);
                dstPort  = RISKY_PORTS[random.nextInt(RISKY_PORTS.length)];
                protocol = "TCP";
                message  = "Connection attempt from " + srcIp + " to risky port " + dstPort;
            }
        }

        return new AlertDto(
            "ALT-" + counter.incrementAndGet(),
            detector, severity, type,
            srcIp, srcPort, dstIp, dstPort,
            protocol, message, timestamp
        );
    }
}
