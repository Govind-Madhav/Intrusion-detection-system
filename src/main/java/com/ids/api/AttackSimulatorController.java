package com.ids.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * api endpoints for the frontend buttons
 * these let you trigger attacks from the website
 *
 * /api/simulate/ddos
 * /api/simulate/port-scan
 * etc..
 */
@RestController
@RequestMapping("/api/simulate")
@CrossOrigin(origins = "*")
public class AttackSimulatorController {

    @Autowired
    private AttackSimulatorService simulatorService;

    @PostMapping("/ddos")
    public Map<String, Object> ddos() {
        int count = simulatorService.simulateDdos();
        return response("DDoS (ICMP Flood)", count, "5 attackers flooding target with ICMP packets");
    }

    @PostMapping("/port-scan")
    public Map<String, Object> portScan() {
        int count = simulatorService.simulatePortScan();
        return response("SYN Port Scan", count, "Swept 15 ports including databases and RDP");
    }

    @PostMapping("/xmas-scan")
    public Map<String, Object> xmasScan() {
        int count = simulatorService.simulateXmasScan();
        return response("Xmas / Stealth Scan", count, "Xmas + NULL + FIN scan combo");
    }

    @PostMapping("/db-breach")
    public Map<String, Object> dbBreach() {
        int count = simulatorService.simulateDbBreach();
        return response("Database Breach", count, "Hit MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch");
    }

    @PostMapping("/brute-force")
    public Map<String, Object> bruteForce() {
        int count = simulatorService.simulateBruteForce();
        return response("Brute Force", count, "12 repeated RDP/SSH authentication attempts");
    }

    @PostMapping("/coordinated")
    public Map<String, Object> coordinated() {
        int count = simulatorService.simulateCoordinated();
        return response("Coordinated Attack", count, "All attack types launched simultaneously");
    }

    private Map<String, Object> response(String scenario, int alertCount, String description) {
        return Map.of(
            "scenario",    scenario,
            "alerts",      alertCount,
            "description", description,
            "status",      "running"
        );
    }
}
