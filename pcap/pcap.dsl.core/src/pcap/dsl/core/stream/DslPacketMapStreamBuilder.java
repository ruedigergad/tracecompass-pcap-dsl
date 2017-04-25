package pcap.dsl.core.stream;

/*
 * Copyright 2017, Ruediger Gad
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 */

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import pcap.dsl.core.config.Constants;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.util.Helper;

/**
 * Stream builder for building streams from the map data contain in
 * {@link PcapDslEvent} instances.
 * 
 * @author &lt;r.c.g@gmx.de&gt;
 *
 */
public class DslPacketMapStreamBuilder {

    private final String protocol;
    private final int nestingLevel;

    private int id = 0;

    private Map<String, DslPacketMapStream> streams = new HashMap<>();
    private Map<Integer, String> ids = new HashMap<>();

    public DslPacketMapStreamBuilder(String protocol, int nestingLevel) {
        this.protocol = protocol;
        this.nestingLevel = nestingLevel;
    }

    public void addEventToStream(PcapDslEvent event) {
        Map<String, Object> packetMap = event.getPacketMap();
        Map<String, Object> nestedMap = Helper.getNestedMap(packetMap, this.nestingLevel);

        if (this.protocol.equals(nestedMap.get(Constants.PACKET_MAP_PROTOCOL_KEY))) {
            System.out.println(protocol + " " + nestingLevel + " "
                    + String.valueOf(nestedMap.get(Constants.PACKET_MAP_SUMMARY_KEY)));

            String aAddress = Helper.getMergedString(packetMap, Constants.PACKET_MAP_SRC_KEY, nestingLevel);
            String bAddress = Helper.getMergedString(packetMap, Constants.PACKET_MAP_DST_KEY, nestingLevel);
            String streamKey = aAddress + bAddress;
            String reverseStreamKey = bAddress + aAddress;

            if (streams.containsKey(streamKey)) {
                streams.get(streamKey).add(packetMap, nestingLevel);
            } else if (streams.containsKey(reverseStreamKey)) {
                streams.get(reverseStreamKey).add(packetMap, nestingLevel);
            } else {
                DslPacketMapStream stream = new DslPacketMapStream(protocol, id, streamKey);
                id++;
                streams.put(streamKey, stream);
                ids.put(id, streamKey);
            }
        }
    }

    public Collection<DslPacketMapStream> getStreams() {
        return streams.values();
    }

}
