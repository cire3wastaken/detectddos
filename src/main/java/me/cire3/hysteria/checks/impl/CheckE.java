package me.cire3.hysteria.checks.impl;

import me.cire3.hysteria.User;
import me.cire3.hysteria.checks.AbstractCheck;
import me.cire3.hysteria.checks.CheckData;
import me.cire3.hysteria.util.EvictingList;
import me.cire3.hysteria.util.MathUtil;
import org.pcap4j.packet.Packet;

import java.util.logging.Logger;

// THESE CHECKS ARE PROOF OF CONCEPT CHECKS
// MORE EFFICIENT AND BETTER CHECKS SHOULD
// BE USED IN PRODUCTION

@CheckData(name = "Check (E)", description = "Generic Heuristic Check", bufferDecay = 0.25)
public class CheckE extends AbstractCheck {
    long lastPacket = -1;
    EvictingList<Long> samples = new EvictingList<>(150);

    public CheckE(User user, Logger logger) {
        super(user, logger);
    }

    @Override
    public boolean checkPacket(Packet pkt) {
        long now = System.nanoTime();
        long delay = now - lastPacket;

        if (delay > 5000000000L && lastPacket != -1) {
            lastPacket = -1;
            samples.clear();
            return false;
        }

        if (lastPacket != -1)
            samples.add(delay);

        final int distinct = MathUtil.getDistinct(this.samples);
        if (distinct < 10 && samples.size() >= 50 && ++buffer > 5) {
            flag(pkt);
            return true;
        }

        lastPacket = now;

        decayBuffer();
        return false;
    }
}
