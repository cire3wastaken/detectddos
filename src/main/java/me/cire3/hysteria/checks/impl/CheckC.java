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

@CheckData(name = "Check (C)", description = "Too low standard deviation", bufferDecay = 0.25)
public class CheckC extends AbstractCheck {
    long lastPacket = -1;
    EvictingList<Long> samples = new EvictingList<>(150);

    public CheckC(User user, Logger logger) {
        super(user, logger);
    }

    @Override
    public boolean checkPacket(Packet pkt) {
        long now = System.currentTimeMillis();
        long delay = now - lastPacket;

        if (delay > 5000 && lastPacket != -1) {
            samples.clear();
            lastPacket = -1;
            return false;
        }

        if (lastPacket != -1)
            samples.add(delay);

        final double deviation = MathUtil.getStandardDeviation(this.samples);

        if (deviation < 167.0 / 100F && samples.size() >= 25 && ++buffer > 5) {
            flag(pkt);
            return true;
        }

        lastPacket = now;

        decayBuffer();
        return false;
    }
}
