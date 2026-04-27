package com.ids.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API for the IDS Dashboard.
 *
 * GET  /api/alerts          - paginated alert history (from MySQL)
 * GET  /api/stats           - summary counters by type and severity (from MySQL)
 * GET  /api/health          - server health check
 * POST /api/alerts/mock     - inject a single mock alert (for testing)
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AlertController {

    @Autowired private AlertStore alertStore;
    @Autowired private AlertRepository alertRepository;
    @Autowired private SimpMessagingTemplate messaging;
    @Autowired private MockDataService mockDataService;

    private final long startTime = System.currentTimeMillis();

    // ──────────────────────────────────────────────────────────────
    // GET /api/alerts?type=&severity=&page=0&size=50
    // Paginated query direct from DB — handles millions of rows fine
    // ──────────────────────────────────────────────────────────────
    @GetMapping("/alerts")
    public Map<String, Object> getAlerts(
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {

        Page<AlertEntity> dbPage = alertRepository.findFiltered(
                type, severity, PageRequest.of(page, size)
        );

        List<AlertDto> alerts = dbPage.getContent()
                .stream()
                .map(AlertEntity::toDto)
                .toList();

        Map<String, Object> resp = new HashMap<>();
        resp.put("alerts", alerts);
        resp.put("total",  dbPage.getTotalElements());
        resp.put("page",   page);
        resp.put("size",   size);
        resp.put("pages",  dbPage.getTotalPages());
        return resp;
    }

    // ──────────────────────────────────────────────────────────────
    // GET /api/stats — all counts from DB (accurate across restarts)
    // ──────────────────────────────────────────────────────────────
    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        long synScan    = alertRepository.countByAlertTypeIgnoreCase("SYN_SCAN");
        long nullScan   = alertRepository.countByAlertTypeIgnoreCase("NULL_SCAN");
        long xmasScan   = alertRepository.countByAlertTypeIgnoreCase("XMAS_SCAN");
        long finScan    = alertRepository.countByAlertTypeIgnoreCase("FIN_SCAN");
        long icmpFlood  = alertRepository.countByAlertTypeIgnoreCase("ICMP_FLOOD");
        long riskyPort  = alertRepository.countByAlertTypeIgnoreCase("RISKY_PORT_ACCESS");
        long critical   = alertRepository.countBySeverityIgnoreCase("CRITICAL");
        long high       = alertRepository.countBySeverityIgnoreCase("HIGH");
        long medium     = alertRepository.countBySeverityIgnoreCase("MEDIUM");
        long low        = alertRepository.countBySeverityIgnoreCase("LOW");

        Map<String, Object> bySeverity = new HashMap<>();
        bySeverity.put("CRITICAL", critical);
        bySeverity.put("HIGH",     high);
        bySeverity.put("MEDIUM",   medium);
        bySeverity.put("LOW",      low);

        Map<String, Object> byType = new HashMap<>();
        byType.put("SYN_SCAN",         synScan);
        byType.put("NULL_SCAN",        nullScan);
        byType.put("XMAS_SCAN",        xmasScan);
        byType.put("FIN_SCAN",         finScan);
        byType.put("ICMP_FLOOD",       icmpFlood);
        byType.put("RISKY_PORT_ACCESS",riskyPort);

        Map<String, Object> stats = new HashMap<>();
        stats.put("total",      alertStore.size());
        stats.put("bySeverity", bySeverity);
        stats.put("byType",     byType);
        // Legacy keys kept for frontend compatibility
        stats.put("synScan",   synScan);
        stats.put("icmpFlood", icmpFlood);
        stats.put("riskyPort", riskyPort);
        return stats;
    }

    // ──────────────────────────────────────────────────────────────
    // GET /api/health
    // ──────────────────────────────────────────────────────────────
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> h = new HashMap<>();
        h.put("status",  "ok");
        h.put("uptime",  System.currentTimeMillis() - startTime);
        h.put("alerts",  alertStore.size());
        return h;
    }

    // ──────────────────────────────────────────────────────────────
    // POST /api/alerts/mock  — inject a single random alert
    // ──────────────────────────────────────────────────────────────
    @PostMapping("/alerts/mock")
    public AlertDto injectMock() {
        AlertDto alert = mockDataService.buildRandomAlert(System.currentTimeMillis());
        alertStore.add(alert);   // persists to DB + updates cache
        messaging.convertAndSend("/topic/alerts", alert);
        return alert;
    }
}
