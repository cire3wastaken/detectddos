package me.cire3.hysteria.checks;

import junit.framework.TestCase;
import me.cire3.hysteria.User;
import org.pcap4j.packet.Packet;

import java.util.logging.Logger;

public class AbstractCheckTest extends TestCase {
    public void testDecay(){
        AbstractCheckImpl check = new AbstractCheckImpl(new User(Logger.getLogger("AbstractCheckTest")),
                Logger.getLogger("AbstractCheckTest"));

        check.buffer++;
        check.decayBuffer();

        assertEquals(1 - 0.125, check.buffer);
    }

    public void testFlag(){
        User mockedUser = new User(Logger.getLogger("AbstractCheckTest"));
        AbstractCheckImpl check = new AbstractCheckImpl(mockedUser,
                Logger.getLogger("AbstractCheckTest"));

        check.flag(null);
        assertEquals(1, mockedUser.getPacketsFlagged());
        assertEquals(1.0F, mockedUser.getTrustFactor());

        // first time decay won't work since just flagged
        check.decayBuffer();

        // so we do it again
        check.decayBuffer();

        float timesFlaggedDivideBy2 = mockedUser.trustFactor / 2F;
        // we flagged so we need to make trust factor 1 not 0
        float mockedTrustFactor = 1;
        if (timesFlaggedDivideBy2 < check.bufferDecay)
            mockedTrustFactor = mockedUser.trustFactor;
        else
            mockedTrustFactor -= check.bufferDecay;

        if (mockedTrustFactor < 0)
            mockedTrustFactor = 0;

        assertEquals(mockedTrustFactor, mockedUser.getTrustFactor());
    }

    @CheckData(name = "", description = "", bufferDecay = 0.125)
    private static class AbstractCheckImpl extends AbstractCheck {
        public AbstractCheckImpl(User user, Logger logger) {
            super(user, logger);
        }

        @Override
        public boolean checkPacket(Packet pkt) {
            return false;
        }
    }
}