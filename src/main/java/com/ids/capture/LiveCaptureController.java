package com.ids.capture;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * endpoints for the live capture buttons on the frontend
 * 
 * /status - checks if its running
 * /interfaces - gets the wifi cards
 * /start - starts the pcap4j thread
 * /stop - stops it
 */
@RestController
@RequestMapping("/api/capture")
@CrossOrigin(origins = "*")
public class LiveCaptureController {

    @Autowired
    private LiveCaptureService captureService;

    @GetMapping("/status")
    public Map<String, Object> status() {
        return Map.of(
            "running",   captureService.isRunning(),
            "interface", captureService.getActiveIface() != null ? captureService.getActiveIface() : "",
            "packets",   captureService.getPackets(),
            "alerts",    captureService.getAlerts(),
            "error",     captureService.getError() != null ? captureService.getError() : ""
        );
    }

    @GetMapping("/interfaces")
    public Map<String, Object> interfaces() {
        List<String> list = captureService.listInterfaces();
        return Map.of("interfaces", list);
    }

    @PostMapping("/start")
    public Map<String, Object> start(
            @RequestParam(defaultValue = "Ethernet") String iface) {

        boolean started = captureService.start(iface);
        if (started) {
            return Map.of(
                "status",    "started",
                "interface", captureService.getActiveIface()
            );
        } else {
            String err = captureService.getError();
            return Map.of(
                "status", "error",
                "error",  err != null ? err : "Already running or interface not found"
            );
        }
    }

    @PostMapping("/stop")
    public Map<String, Object> stop() {
        captureService.stop();
        return Map.of(
            "status",  "stopped",
            "packets", captureService.getPackets(),
            "alerts",  captureService.getAlerts()
        );
    }
}
