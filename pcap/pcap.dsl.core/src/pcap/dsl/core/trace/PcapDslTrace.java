package pcap.dsl.core.trace;

import java.util.Collection;

import org.eclipse.core.resources.IResource;
import org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfBaseAspects;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfTraceException;

import com.google.common.collect.ImmutableList;

import pcap.dsl.core.aspects.PcapDslDestinationAspect;
import pcap.dsl.core.aspects.PcapDslProtocolAspect;
import pcap.dsl.core.aspects.PcapDslReferenceAspect;
import pcap.dsl.core.aspects.PcapDslSourceAspect;

public class PcapDslTrace extends PcapTrace {

    private static final Collection<ITmfEventAspect<?>> PCAP_DSL_ASPECTS =
            ImmutableList.of(
                    TmfBaseAspects.getTimestampAspect(),
                    PcapDslSourceAspect.INSTANCE,
                    PcapDslDestinationAspect.INSTANCE,
                    PcapDslProtocolAspect.INSTANCE,
                    PcapDslReferenceAspect.INSTANCE,
                    TmfBaseAspects.getContentsAspect()
                    );
    
	@Override
    public synchronized void initTrace(IResource resource, String path, Class<? extends ITmfEvent> type) throws TmfTraceException {
		System.out.println("PcapDslTrace.initTrace(...)");
        super.initTrace(resource, path, type);
	}
	
    @Override
    public Iterable<ITmfEventAspect<?>> getEventAspects() {
        return PCAP_DSL_ASPECTS;
    }
}
