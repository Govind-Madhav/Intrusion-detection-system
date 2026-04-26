package com.ids.app;

import com.ids.capture.InterfaceSelector;
import com.ids.capture.PacketCaptureService;
import com.ids.config.CliArgs;
import com.ids.model.PacketData;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.NotOpenException;

import java.util.List;
import java.time.Instant;

public class Application {

    public static void main(String[] args) {
        try {
            CliArgs cliArgs = CliArgs.parse(args);
            
            if (cliArgs.isVerbose()) {
                System.out.println("[DEBUG] Configuration: " + cliArgs);
            }

            // Select interface
            PcapNetworkInterface networkInterface = InterfaceSelector.select(cliArgs.getInterfaceName());
            System.out.printf("[INFO] Capturing %d packets from interface: %s (%s)%n",
                    cliArgs.getPacketCount(), networkInterface.getName(), networkInterface.getDescription());

            // Perform capture
            long startTime = System.currentTimeMillis();
            try (PacketCaptureService captureService = new PacketCaptureService(cliArgs.getSnapLen(), cliArgs.getTimeoutMillis())) {
                List<PacketData> packets = captureService.capture(networkInterface, cliArgs.getPacketCount());
                long duration = System.currentTimeMillis() - startTime;

                // Report statistics
                PacketCaptureService.CaptureStatistics stats = captureService.getStatistics();
                System.out.printf("[INFO] Captured %d packets in %dms (failed: %d)%n", 
                        stats.processed, duration, stats.failed);

                if (packets.isEmpty()) {
                    System.out.println("[WARN] No packets were captured within the timeout period.");
                    return;
                }

                // Output captured packets
                if (cliArgs.isVerbose()) {
                    System.out.println("[DEBUG] Detailed packet output:");
                    for (PacketData packet : packets) {
                        System.out.println(packet);
                    }
                } else {
                    System.out.printf("[INFO] Successfully captured %d packets ready for analysis%n", packets.size());
                }
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println("[ERROR] " + e.getMessage());
            try {
                InterfaceSelector.printAvailableInterfaces();
            } catch (PcapNativeException ignored) {
                System.err.println("[ERROR] Unable to list interfaces.");
            }
            System.exit(1);
        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("[ERROR] Packet capture failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
