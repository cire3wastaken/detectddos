package me.cire3.hysteria;

import lombok.Getter;
import me.cire3.hysteria.handler.PacketSendListener;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.util.logging.Logger;

public enum Hysteria {
    HYSTERIA;

    @Getter
    private static final Logger logger = Logger.getLogger(Hysteria.class.getSimpleName());

    public void start(String[] args) {
        try {
            PacketSendListener.startListening(User.getInstance(logger), logger);
        } catch (PcapNativeException | NotOpenException e) {
            logger.severe(e.toString());
        }
    }
}
