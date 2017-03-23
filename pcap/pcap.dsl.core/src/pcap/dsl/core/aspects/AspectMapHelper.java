package pcap.dsl.core.aspects;

import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;

import pcap.dsl.core.config.Constants;
import pcap.dsl.core.event.PcapDslEvent;

public class AspectMapHelper {

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
