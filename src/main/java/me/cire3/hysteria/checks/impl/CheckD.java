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

@CheckData(name = "Check (D)", description = "Too low skewness", bufferDecay = 0.25)
public class CheckD extends AbstractCheck {
    long lastPacket = -1;
    EvictingList<Long> samples = new EvictingList<>(150);

    public CheckD(User user, Logger logger) {
        super(user, logger);
    }

    @Override
    public boolean checkPacket(Packet pkt) {
        long now = System.currentTimeMillis();
        long delay = now - lastPacket;

        if (delay > 5000 && lastPacket != -1) {
            lastPacket = -1;
            samples.clear();
            return false;
        }

        if (lastPacket != -1)
            samples.add(delay);

        final double skewness = MathUtil.getSkewness(this.samples);

        if (skewness < -0.01 && samples.size() >= 25 && ++buffer > 5) {
            flag(pkt);
            return true;
        }

        lastPacket = now;

        decayBuffer();
        return false;
    }
}
