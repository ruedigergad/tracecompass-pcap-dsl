package pcap.dsl.core.event;

/*
 * Copyright 2017, Ruediger Gad and others (See comments "@@@@@" in source code.)
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 * The other parts of this file that were taken from existing code
 * (Marked with "@@@@@".) were also licensed under the terms of the EPL.
 * 
 */

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.tracecompass.internal.pcap.core.protocol.pcap.PcapPacket;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;
import org.eclipse.tracecompass.internal.pcap.core.util.ConversionHelper;
import org.eclipse.tracecompass.internal.pcap.core.util.PcapTimestampScale;
import org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.TmfEventField;
import org.eclipse.tracecompass.tmf.core.event.TmfEventType;
import org.eclipse.tracecompass.tmf.core.timestamp.ITmfTimestamp;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimestamp;

import pcap.dsl.core.config.Constants;
import pcap.dsl.core.trace.PcapDslFile;

/**
 * 
 * @author Ruediger Gad &lt;r.c.g@gmx.de&gt; and others (See comments "@@@@@" in
 *         source code.)
 *
 */
public class PcapDslEventFactory {

    public static PcapDslEvent createEvent(Map<String, Object> packetMap, PcapFile pcapFile, PcapTrace pcapTrace) {

        if (!(packetMap.get(PcapDslFile.PCAP_HEADER) instanceof ByteBuffer)) {
            throw new RuntimeException("Invalid pcap header.");
        }

        ByteBuffer packetHeader = (ByteBuffer) packetMap.get(PcapDslFile.PCAP_HEADER);

        long rank = 0;
        if (packetMap.get(PcapDslFile.PCAP_RANK) instanceof Long) {
            rank = (long) packetMap.get(PcapDslFile.PCAP_RANK);
        }

        List<ITmfEventField> fieldList = new ArrayList<>();
        fillEventFieldListContent(packetMap, fieldList, 0);

        ITmfEventField[] fieldArray = fieldList.toArray(new ITmfEventField[fieldList.size()]);
        ITmfEventField rootEventField =  new TmfEventField(ITmfEventField.ROOT_FIELD_ID, null, fieldArray);

        ITmfTimestamp tmfTimestamp = getTimestamp(pcapFile, pcapTrace, packetHeader);
        return new PcapDslEvent(pcapTrace, rank, tmfTimestamp, new TmfEventType("DSL-extracted Pcap Trace", null),
                rootEventField, packetMap);
    }

    private static void fillEventFieldListContent(Map<String, Object> contentMap, List<ITmfEventField> fieldList,
            int nestingLevel) {

        List<ITmfEventField> subfieldList = new ArrayList<>();
        String subfieldLabel = null;

        for (Map.Entry<String, Object> entry : contentMap.entrySet()) {
            final String k = entry.getKey();
            final Object v = entry.getValue();

            if (k.startsWith("__")) {
                continue;
            }

            if (!(v instanceof Map)) {
                subfieldList.add(new TmfEventField(k, v, null));

                if (k.equals(Constants.PACKET_MAP_PROTOCOL_KEY)) {
                    subfieldLabel = String.valueOf(v);
                }
            } else {
                fillEventFieldListContent((Map<String, Object>) v, fieldList, ++nestingLevel);
            }
        }

        if (subfieldLabel == null) {
            subfieldLabel = String.valueOf(nestingLevel);
        }

        ITmfEventField[] subfieldArray = subfieldList.toArray(new ITmfEventField[subfieldList.size()]);
        fieldList.add(new PcapDslEventField(subfieldLabel, "", subfieldArray, contentMap));
    }

    private static ITmfTimestamp getTimestamp(PcapFile pcapFile, PcapTrace pcapTrace, ByteBuffer packetHeader) {
        /*
         * @@@@@@ The timestamp conversion was taken from PcapPacket.
         */
        packetHeader.order(pcapFile.getByteOrder());
        packetHeader.position(0);
        long timestampMostSignificant = ConversionHelper.unsignedIntToLong(packetHeader.getInt());
        long timestampLeastSignificant = ConversionHelper.unsignedIntToLong(packetHeader.getInt());

        long timestamp = 0;
        PcapTimestampScale scale = pcapFile.getTimestampPrecision();
        switch (scale) {
        case MICROSECOND:
            if (timestampLeastSignificant > PcapPacket.TIMESTAMP_MICROSECOND_MAX) {
                throw new RuntimeException("The timestamp is erroneous."); //$NON-NLS-1$
            }
            timestamp = PcapPacket.TIMESTAMP_MICROSECOND_MAX * timestampMostSignificant + timestampLeastSignificant;
            break;
        case NANOSECOND:
            if (timestampLeastSignificant > PcapPacket.TIMESTAMP_NANOSECOND_MAX) {
                throw new RuntimeException("The timestamp is erroneous."); //$NON-NLS-1$
            }
            timestamp = PcapPacket.TIMESTAMP_NANOSECOND_MAX * timestampMostSignificant + timestampLeastSignificant;
            break;
        default:
            throw new IllegalArgumentException("The timestamp precision is not valid!"); //$NON-NLS-1$
        }

        /*
         * @@@@@@ The timestamp handling was taken from PcapEventFactory.
         */
        ITmfTimestamp tmfTimestamp;
        switch (scale) {
        case MICROSECOND:
            long us = pcapTrace.getTimestampTransform().transform(timestamp * 1000) / 1000;
            tmfTimestamp = TmfTimestamp.fromMicros(us);
            break;
        case NANOSECOND:
            long ns = pcapTrace.getTimestampTransform().transform(timestamp);
            tmfTimestamp = TmfTimestamp.fromNanos(ns);
            break;
        default:
            throw new IllegalArgumentException("The timestamp precision is not valid!"); //$NON-NLS-1$
        }

        return tmfTimestamp;
    }
}
