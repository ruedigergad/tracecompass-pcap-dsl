package pcap.dsl.core.event;

import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventType;
import org.eclipse.tracecompass.tmf.core.event.TmfEvent;
import org.eclipse.tracecompass.tmf.core.timestamp.ITmfTimestamp;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

public class PcapDslEvent extends TmfEvent {

    private Map<String, Object> packetMap;

    public PcapDslEvent(ITmfTrace trace, long rank, ITmfTimestamp timestamp, ITmfEventType type, ITmfEventField content,
            Map<String, Object> packetMap) {
        super(trace, rank, timestamp, type, content);
        this.packetMap = packetMap;
    }

    public Map<String, Object> getPacketMap() {
        return this.packetMap;
    }
}
