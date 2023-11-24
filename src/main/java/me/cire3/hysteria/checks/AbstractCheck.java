package me.cire3.hysteria.checks;

import lombok.Getter;
import lombok.Setter;
import me.cire3.hysteria.User;
import org.pcap4j.packet.Packet;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractCheck {
    @Getter
    protected final String name;
    @Getter
    protected final String description;
    @Getter
    protected final double bufferDecay;

    protected double buffer;

    private boolean flagged;

    @Getter
    private final User user;

    @Getter
    @Setter
    protected Logger logger;

    public AbstractCheck(User user, Logger logger) {
        if (!getClass().isAnnotationPresent(CheckData.class))
            throw new IllegalStateException("No CheckData Annotation Present!");
        CheckData checkData = getClass().getAnnotation(CheckData.class);
        name = checkData.name();
        description = checkData.description();
        bufferDecay = checkData.bufferDecay();
        this.user = user;
        this.logger = logger;
    }

    public abstract boolean checkPacket(Packet pkt);

    protected final void flag(Packet pkt) {
        logger.log(Level.WARNING,
                "Check Type: " + name + " (" + description + ") Packet was detected to be DDoS. Now: " + System.currentTimeMillis());

        // Unfortunately for this PoC implementation, pcap4j
        // does not support cancelling sending these packets,
        // so I comment this out. However, when implemented
        // on the router, it should be properly cancelled

        // pkt.cancel();

        user.flag();
        flagged = true;
    }

    protected final void decayBuffer() {
        if (flagged) {
            flagged = false;
            return;
        }

        buffer -= bufferDecay;
        if (buffer < 0)
            buffer = 0;

        float timesFlaggedDivideBy2 = user.trustFactor / 2F;

        if (timesFlaggedDivideBy2 < bufferDecay)
            user.trustFactor /= 2F;
        else
            user.trustFactor -= bufferDecay;

        if (user.trustFactor < 0)
            user.trustFactor = 0;
    }
}
