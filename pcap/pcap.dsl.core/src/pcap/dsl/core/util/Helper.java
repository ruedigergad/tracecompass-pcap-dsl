package pcap.dsl.core.util;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.request.ITmfEventRequest;
import org.eclipse.tracecompass.tmf.core.request.TmfEventRequest;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimeRange;

import pcap.dsl.core.config.Constants;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.trace.PcapDslTrace;

public class Helper {

    private Helper() {
        // No instances allowed of Helper class.
    }

    public static Map<String, Object> getNestedMap(Map<String, Object> parentMap, int nestingLevel) {
        Map<String, Object> tmpMap = parentMap;
        int currentNestingLevel = 0;

        while (tmpMap != null && currentNestingLevel < nestingLevel) {
            if (tmpMap.get(Constants.PACKET_MAP_DATA_KEY) instanceof Map<?, ?>) {
                tmpMap = (Map<String, Object>) tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                currentNestingLevel++;
            } else {
                tmpMap = null;
            }
        }

        return tmpMap;
    }

    public static Map<String, Integer> getProtocolMap(PcapDslTrace trace) {
        Map<String, Integer> protocolMap = new HashMap<>();

        if (trace != null) {
            // ITmfEventRequest request = fRequest;
            // if ((request != null) && (!request.isCompleted())) {
            // request.cancel();
            // }

            ITmfEventRequest request = new TmfEventRequest(PcapDslEvent.class, TmfTimeRange.ETERNITY, 0L,
                    ITmfEventRequest.ALL_DATA, ITmfEventRequest.ExecutionType.BACKGROUND) {

                @Override
                public void handleData(ITmfEvent data) {
                    // Called for each event
                    super.handleData(data);
                    if (!(data instanceof PcapDslEvent)) {
                        return;
                    }
                    PcapDslEvent event = (PcapDslEvent) data;

                    int nestingLevel = 0;
                    Map<String, Object> tmpMap = event.getPacketMap();
                    while (tmpMap != null) {
                        Object proto = tmpMap.get(Constants.PACKET_MAP_PROTOCOL_KEY);
                        if (proto instanceof String && !protocolMap.containsKey(proto)) {
                            protocolMap.put((String) proto, nestingLevel);
                        }

                        Object tmpData = tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                        if (tmpData instanceof Map<?, ?>) {
                            tmpMap = (Map<String, Object>) tmpData;
                        } else {
                            tmpMap = null;
                        }
                        nestingLevel++;
                    }
                }
            };
            trace.sendRequest(request);

            try {
                request.waitForCompletion();
            } catch (InterruptedException e) {
                // Request was canceled.
                return new HashMap<String, Integer>();
            }

            System.out.println("Got protocolMap: " + String.valueOf(protocolMap));
        }

        return protocolMap;
    }

    public static String getMergedString(Map<String, Object> packetMap, String key, int nestingLevel) {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> tmpMap = packetMap;
        int currentNestingLevel = 0;

        while (tmpMap != null && currentNestingLevel <= nestingLevel) {
            if (tmpMap.containsKey(key) && tmpMap.get(Constants.PACKET_MAP_DATA_KEY) instanceof Map<?, ?>) {
                sb.append(tmpMap.get(key));
                sb.append(Constants.SEPARATOR);
                
                tmpMap = (Map<String, Object>) tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                currentNestingLevel++;
            } else {
                tmpMap = null;
            }
        }

        return sb.toString();
    }
}
