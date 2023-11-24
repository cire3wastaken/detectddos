package me.cire3.hysteria.checks.impl;

import me.cire3.hysteria.User;
import me.cire3.hysteria.checks.AbstractCheck;
import me.cire3.hysteria.checks.CheckData;
import me.cire3.hysteria.util.TimerUtil;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

// THESE CHECKS ARE PROOF OF CONCEPT CHECKS
// MORE EFFICIENT AND BETTER CHECKS SHOULD
// BE USED IN PRODUCTION

@CheckData(name = "Check (A)", description = "High Packets / Second", bufferDecay = 0.5)
public class CheckA extends AbstractCheck {
    List<Long> packets = new ArrayList<>();
    int tillNextDecay;

    // prevent false flags from loading webpages too fast
    TimerUtil lastPacketSent;

    public CheckA(User user, Logger logger) {
        super(user, logger);
        lastPacketSent = new TimerUtil();
    }

    @Override
    public boolean checkPacket(Packet pkt) {
        // remove packets from more than a second ago
        packets.removeIf(e -> System.currentTimeMillis() - e > 1000);

        if (lastPacketSent.elapsed(2000)) {
            lastPacketSent.reset();
            packets.clear();
        }

        if (packets.size() >= 500) {
            if (++buffer > 3) {
                flag(pkt);
                return true;
            }
            packets.clear();
            tillNextDecay = 300;
        }

        packets.add(System.currentTimeMillis());

        if (tillNextDecay-- <= 0) {
            decayBuffer();
            tillNextDecay = 0;
        }

        lastPacketSent.reset();
        return false;
    }
}
