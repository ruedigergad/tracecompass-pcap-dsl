package pcap.dsl.core.event;

/*
 * Copyright 2017, Ruediger Gad
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 */

import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventType;
import org.eclipse.tracecompass.tmf.core.event.TmfEvent;
import org.eclipse.tracecompass.tmf.core.timestamp.ITmfTimestamp;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

/**
 * Event for wrapping map-based packet header data as extracted via the dsbdp
 * DSL.
 * 
 * @author &lt;r.c.g@gmx.de&gt;
 *
 */
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
