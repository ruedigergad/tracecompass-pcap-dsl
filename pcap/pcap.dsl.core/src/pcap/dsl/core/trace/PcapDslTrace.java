package pcap.dsl.core.trace;

import org.eclipse.core.resources.IResource;
import org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfTraceException;

public class PcapDslTrace extends PcapTrace {

	@Override
    public synchronized void initTrace(IResource resource, String path, Class<? extends ITmfEvent> type) throws TmfTraceException {
		System.out.println("PcapDslTrace.initTrace(...)");
        super.initTrace(resource, path, type);
	}
}
