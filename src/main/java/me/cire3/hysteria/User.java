package me.cire3.hysteria;

import lombok.Getter;
import lombok.Setter;
import me.cire3.hysteria.checks.CheckManager;

import java.util.logging.Logger;

public class User {
    // we use a singleton since we aren't listening where multiple people connect
    // this is a proof of concept implementation to "prevent" ddos packets
    // per computer basis. This should be implemented on the router however
    // and will need proper user management.
    private static User GLOBAL_INSTANCE;

    // higher trust factor is bad
    @Getter
    @Setter
    public float trustFactor;

    @Getter
    private int packetsFlagged;

    @Getter
    private final CheckManager checkManager;

    @Getter
    private final Logger logger;

    public User(Logger logger) {
        this.logger = logger;
        this.checkManager = new CheckManager(this, logger);
    }

    public static User getInstance(Logger logger){
        return GLOBAL_INSTANCE == null ? GLOBAL_INSTANCE = new User(logger) : GLOBAL_INSTANCE;
    }

    public void flag() {
        trustFactor++;
        packetsFlagged++;
    }
}
