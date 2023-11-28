package me.cire3.hysteria.checks.impl;

import me.cire3.hysteria.User;
import me.cire3.hysteria.checks.AbstractCheck;
import me.cire3.hysteria.checks.CheckData;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

// THESE CHECKS ARE PROOF OF CONCEPT CHECKS
// MORE EFFICIENT AND BETTER CHECKS SHOULD
// BE USED IN PRODUCTION

@CheckData(name = "Check (B" +
        ")", description = "Generic Heuristic Check", bufferDecay = 0.25)
public class CheckB extends AbstractCheck {
    Map<String, List<Long>> urlToTime = new HashMap<>();

    public CheckB(User user, Logger logger) {
        super(user, logger);
    }

    @Override
    public boolean checkPacket(Packet pkt) {
        Map<String, List<Long>> newUrlToTime = new HashMap<>();

        for (String url : urlToTime.keySet()) {
            url = url.toLowerCase();

            List<Long> timesRequested = urlToTime.get(url);
            List<Long> newTimesRequested = new ArrayList<>();

            for (Long timeRequested : timesRequested){
                if (System.currentTimeMillis() - timeRequested < 60 * 1000)
                    newTimesRequested.add(timeRequested);
            }

            newUrlToTime.put(url, newTimesRequested);
        }

        urlToTime.clear();
        urlToTime.putAll(newUrlToTime);

        if (pkt.get(IpV4Packet.class) == null)
            return false;

        // https://github.com/kaitoy/pcap4j/issues/182
        Inet4Address destAddressObj = pkt.get(IpV4Packet.class).getHeader().getDstAddr();
        String destAddress = destAddressObj.toString();

        List<Long> list = urlToTime.remove(destAddress);

        if (list == null)
            list = new ArrayList<>();

        list.add(System.currentTimeMillis());

        urlToTime.put(destAddress, list);

        int howManyTimesRequested = urlToTime.get(destAddress).size();

        if (howManyTimesRequested >= urlToTime.size() / 1.5F && howManyTimesRequested >= 100) {
            if (++buffer > 15) {
                flag(pkt);
                urlToTime.clear();
                return true;
            }
        }

        decayBuffer();
        return false;
    }
}
