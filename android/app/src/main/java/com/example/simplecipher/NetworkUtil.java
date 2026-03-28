package com.example.simplecipher;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class NetworkUtil {
  private NetworkUtil() {}

  static List<String> getLocalIps() {
    List<String> ipv4 = new ArrayList<>();
    List<String> ipv6 = new ArrayList<>();
    try {
      for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
        if (!ni.isUp() || ni.isLoopback()) continue;
        for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
          if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()) continue;
          String ip = addr.getHostAddress();
          if (addr instanceof Inet6Address) {
            ip = ip.replaceAll("%.*", "");
            ipv6.add(ip);
          } else {
            ipv4.add(ip);
          }
        }
      }
    } catch (SocketException ignored) {
    }
    /* Prefer IPv4 -- shorter, easier to read aloud and type.
     * Only show IPv6 if no IPv4 addresses are available. */
    return ipv4.isEmpty() ? ipv6 : ipv4;
  }
}
