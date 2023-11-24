package me.cire3.hysteria.checks;

import lombok.Getter;
import me.cire3.hysteria.User;
import me.cire3.hysteria.checks.impl.*;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class CheckManager {
    @Getter
    private final User user;

    @Getter
    private final List<AbstractCheck> checksToRun = new ArrayList<>();

    @Getter
    private final Logger logger;

    public CheckManager(User user, Logger logger) {
        this.user = user;
        this.logger = logger;
        checksToRun.add(new CheckA(user, logger));
        checksToRun.add(new CheckB(user, logger));
        checksToRun.add(new CheckC(user, logger));
        checksToRun.add(new CheckD(user, logger));
        checksToRun.add(new CheckE(user, logger));
    }

    public void check(Packet pkt) {
        for (AbstractCheck check : checksToRun) {
            if (check.checkPacket(pkt))
                break;
        }
    }
}
