package pcap.dsl.core.event;

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

        ITmfTimestamp tmfTimestamp = getTimestamp(pcapFile, pcapTrace, packetHeader);
        ITmfEventField rootEventField = createEventFieldContent(packetMap);

        return new PcapDslEvent(pcapTrace, rank, tmfTimestamp, new TmfEventType("DSL-extracted Pcap Trace", null),
                rootEventField, packetMap);
    }

    private static ITmfEventField createEventFieldContent(Map<String, Object> packetMap) {
        List<ITmfEventField> fieldList = new ArrayList<>();
        List<ITmfEventField> subfieldList = new ArrayList<>();

        Map<String, Object> tmpMap = packetMap;
        int nestingLevel = 0;

        while (tmpMap != null) {
            subfieldList.clear();
            String subfieldLabel = null;

            for (Map.Entry<String, Object> entry : tmpMap.entrySet()) {
                final String k = entry.getKey();
                if (k != null && !k.equals(Constants.PACKET_MAP_DATA_KEY) && !k.startsWith("__")) {
                    subfieldList.add(new TmfEventField(k, entry.getValue(), null));

                    if (k.equals(Constants.PACKET_MAP_PROTOCOL_KEY)) {
                        subfieldLabel = String.valueOf(entry.getValue());
                    }
                }
            }

            if (subfieldLabel == null) {
                subfieldLabel = String.valueOf(nestingLevel);
            }

            ITmfEventField[] subfieldArray = subfieldList.toArray(new ITmfEventField[subfieldList.size()]);
            fieldList.add(new PcapDslEventField(subfieldLabel, "", subfieldArray, tmpMap));

            nestingLevel++;
            Object data = tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
            if (data instanceof Map<?, ?>) {
                tmpMap = (Map<String, Object>) data;
            } else {
                tmpMap = null;
            }
        }

        ITmfEventField[] fieldArray = fieldList.toArray(new ITmfEventField[fieldList.size()]);
        return new TmfEventField(ITmfEventField.ROOT_FIELD_ID, null, fieldArray);
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
