package pcap.dsl.core.aspects;

/*
 * Copyright 2017, Ruediger Gad
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 */

import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;

import pcap.dsl.core.config.Constants;
import pcap.dsl.core.event.PcapDslEvent;

/**
 * 
 * @author Ruediger Gad &lt;r.c.g@gmx.de&gt;
 *
 */
public class AspectMapHelper {

    /**
     * ev is expected to be a {@link PcapDslEvent} instance that contains a map
     * representation of packet header data as returned by dsbdp. This method
     * processes the nested map structure extracting the fields with the given
     * fieldName for each protocol and concatenates them.
     * 
     * @param ev
     * @param fieldName
     * @return
     */
    public static String concatFields(ITmfEvent ev, String fieldName) {
        if (ev instanceof PcapDslEvent) {
            PcapDslEvent event = (PcapDslEvent) ev;

            Map<String, Object> tmpMap = event.getPacketMap();

            StringBuilder sb = new StringBuilder();

            while (tmpMap != null) {
                if (tmpMap.containsKey(fieldName)) {
                    sb.append(String.valueOf(tmpMap.get(fieldName)));
                    sb.append("|");
                }

                Object data = tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                if (data instanceof Map<?, ?>) {
                    tmpMap = (Map<String, Object>) data;
                } else {
                    tmpMap = null;
                }
            }

            if (sb.length() > 1) {
                sb.deleteCharAt(sb.length() - 1);
            }

            return sb.toString();
        }

        return "n/a";
    }

}
