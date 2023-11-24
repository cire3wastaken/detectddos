package me.cire3.hysteria.handler;

import com.sun.jna.Platform;
import lombok.Getter;
import me.cire3.hysteria.User;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.logging.Logger;

@Getter
public class PacketSendListener {
    private static final String COUNT_KEY = PacketSendListener.class.getName() + ".count";
//    private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);
    private static final int COUNT = 500;

    private static final String READ_TIMEOUT_KEY = PacketSendListener.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = PacketSendListener.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final String BUFFER_SIZE_KEY = PacketSendListener.class.getName() + ".bufferSize";
    private static final int BUFFER_SIZE =
            Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

    private static final String TIMESTAMP_PRECISION_NANO_KEY =
            PacketSendListener.class.getName() + ".timestampPrecision.nano";
    private static final boolean TIMESTAMP_PRECISION_NANO =
            Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

    private static final String NIF_NAME_KEY = PacketSendListener.class.getName() + ".nifName";
    private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

    public static void startListening(User user, Logger logger) throws PcapNativeException, NotOpenException {
        String filter = "";

        logger.info(COUNT_KEY + ": " + COUNT);
        logger.info(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        logger.info(SNAPLEN_KEY + ": " + SNAPLEN);
        logger.info(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
        logger.info(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
        logger.info(NIF_NAME_KEY + ": " + NIF_NAME);
        logger.info("\n");

        PcapNetworkInterface nif;
        if (NIF_NAME != null) {
            nif = Pcaps.getDevByName(NIF_NAME);
        } else {
            try {
                nif = new NifSelector().selectNetworkInterface();
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }

            if (nif == null) {
                return;
            }
        }

        logger.info(nif.getName() + " (" + nif.getDescription() + ")");
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() != null) {
                logger.info("IP address: " + addr.getAddress());
            }
        }
        logger.info("");

        PcapHandle.Builder phb =
                new PcapHandle.Builder(nif.getName())
                        .snaplen(SNAPLEN)
                        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                        .timeoutMillis(READ_TIMEOUT)
                        .bufferSize(BUFFER_SIZE);
        if (TIMESTAMP_PRECISION_NANO) {
            phb.timestampPrecision(PcapHandle.TimestampPrecision.NANO);
        }
        PcapHandle handle = phb.build();

        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        long beginTime = System.currentTimeMillis();
        int num = 0;
        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet != null) {
                num++;
                user.getCheckManager().check(packet);

                if (user.getTrustFactor() > 500)
                    break;
            }
        }

        PcapStat ps = handle.getStats();
        logger.info("ps_recv: " + ps.getNumPacketsReceived());
        logger.info("ps_drop: " + ps.getNumPacketsDropped());
        logger.info("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
            logger.info("bs_capt: " + ps.getNumPacketsCaptured());
        }

        logger.info("Flagged Packets: " + user.getPacketsFlagged());
        logger.info("Packets Sent: " + num);
        logger.info("Would be cancelled: " + ((float) user.getPacketsFlagged()) / num);

        handle.close();
    }
}
