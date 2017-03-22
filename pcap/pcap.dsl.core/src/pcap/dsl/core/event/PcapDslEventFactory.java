package pcap.dsl.core.event;

import java.util.Map;

import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;
import org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace;
import org.eclipse.tracecompass.tmf.core.event.TmfEventType;

import pcap.dsl.core.trace.PcapDslFile;

public class PcapDslEventFactory {

    public static PcapDslEvent createEvent(Map<String, Object> packetMap, PcapFile pcapFile, PcapTrace pcapTrace) {
        
        long rank = 0;
        if (packetMap.get(PcapDslFile.PCAP_RANK) instanceof Long) {
            rank = (long) packetMap.get(PcapDslFile.PCAP_RANK);
        }
        
        return new PcapDslEvent(pcapTrace, rank, null, new TmfEventType("DSL-extracted Pcap Trace", null), null);
    }
}
