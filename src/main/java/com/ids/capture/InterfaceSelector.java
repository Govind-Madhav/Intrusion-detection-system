package com.ids.capture;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;
import java.util.Optional;

public class InterfaceSelector {

    public static List<PcapNetworkInterface> listAllInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    public static void printAvailableInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = listAllInterfaces();
        if (interfaces == null || interfaces.isEmpty()) {
            System.out.println("No network interfaces found.");
            return;
        }

        System.out.println("Available network interfaces:");
        for (PcapNetworkInterface nif : interfaces) {
            System.out.printf("- %s (%s)%n", nif.getName(), nif.getDescription());
        }
    }

    public static PcapNetworkInterface select(String interfaceName) throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = listAllInterfaces();
        if (interfaces == null || interfaces.isEmpty()) {
            throw new IllegalStateException("No network interfaces are available for capture.");
        }

        if (interfaceName == null || interfaceName.isBlank()) {
            return interfaces.get(0);
        }

        Optional<PcapNetworkInterface> match = interfaces.stream()
                .filter(nif -> interfaceName.equalsIgnoreCase(nif.getName())
                        || interfaceName.equalsIgnoreCase(nif.getDescription())
                        || (nif.getDescription() != null && nif.getDescription().toLowerCase().contains(interfaceName.toLowerCase())))
                .findFirst();

        if (match.isPresent()) {
            return match.get();
        }

        throw new IllegalArgumentException("Network interface not found: " + interfaceName);
    }
}

