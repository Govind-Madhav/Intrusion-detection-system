package com.ids.app;

import com.ids.capture.InterfaceSelector;
import com.ids.capture.PacketCaptureService;
import com.ids.config.CliArgs;
import com.ids.model.PacketData;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.NotOpenException;

import java.util.List;

public class Application {

    public static void main(String[] args) {
        CliArgs cliArgs = CliArgs.parse(args);

        try {
            PcapNetworkInterface networkInterface = InterfaceSelector.select(cliArgs.getInterfaceName());
            System.out.printf("Capturing %d packets from interface: %s (%s)%n",
                    cliArgs.getPacketCount(), networkInterface.getName(), networkInterface.getDescription());

            PacketCaptureService captureService = new PacketCaptureService(cliArgs.getSnapLen(), cliArgs.getTimeoutMillis());
            List<PacketData> packets = captureService.capture(networkInterface, cliArgs.getPacketCount());

            if (packets.isEmpty()) {
                System.out.println("No packets were captured within the timeout period.");
                return;
            }

            for (PacketData packet : packets) {
                System.out.println(packet);
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println(e.getMessage());
            try {
                InterfaceSelector.printAvailableInterfaces();
            } catch (PcapNativeException ignored) {
                System.err.println("Unable to list interfaces.");
            }
        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("Packet capture failed: " + e.getMessage());
        }
    }
}
