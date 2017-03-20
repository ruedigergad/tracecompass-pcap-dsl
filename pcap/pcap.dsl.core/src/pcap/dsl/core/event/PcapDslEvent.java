package pcap.dsl.core.event;

import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventType;
import org.eclipse.tracecompass.tmf.core.event.TmfEvent;
import org.eclipse.tracecompass.tmf.core.timestamp.ITmfTimestamp;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

public class PcapDslEvent extends TmfEvent {

    public PcapDslEvent(ITmfTrace trace, long rank, ITmfTimestamp timestamp, ITmfEventType type,
            ITmfEventField content) {
        super(trace, rank, timestamp, type, content);
    }
}
