package pcap.dsl.core.trace;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Map;

import org.eclipse.core.resources.IResource;
import org.eclipse.tracecompass.internal.pcap.core.packet.BadPacketException;
import org.eclipse.tracecompass.internal.pcap.core.trace.BadPcapFileException;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;
import org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.TmfEventType;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfBaseAspects;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfTraceException;
import org.eclipse.tracecompass.tmf.core.trace.ITmfContext;

import com.google.common.collect.ImmutableList;

import pcap.dsl.core.aspects.PcapDslDestinationAspect;
import pcap.dsl.core.aspects.PcapDslProtocolAspect;
import pcap.dsl.core.aspects.PcapDslReferenceAspect;
import pcap.dsl.core.aspects.PcapDslSourceAspect;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.event.PcapDslEventFactory;

public class PcapDslTrace extends PcapTrace {

    private static final Collection<ITmfEventAspect<?>> PCAP_DSL_ASPECTS = ImmutableList.of(
            TmfBaseAspects.getTimestampAspect(), PcapDslSourceAspect.INSTANCE, PcapDslDestinationAspect.INSTANCE,
            PcapDslProtocolAspect.INSTANCE, PcapDslReferenceAspect.INSTANCE, TmfBaseAspects.getContentsAspect());

    @Override
    public synchronized void initTrace(IResource resource, String path, Class<? extends ITmfEvent> type)
            throws TmfTraceException {
        System.out.println("PcapDslTrace.initTrace(...)");

        super.initTrace(resource, path, type);

        try {
            fPcapFile = new PcapDslFile(Paths.get(path));
        } catch (IOException | BadPcapFileException e) {
            throw new TmfTraceException(e.getMessage(), e);
        }
    }

    @Override
    public Iterable<ITmfEventAspect<?>> getEventAspects() {
        return PCAP_DSL_ASPECTS;
    }

    /*
     * (non-Javadoc)
     * 
     * @@@@@ Taken from PcapTrace:
     * 
     * @see org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace#
     * parseEvent(org.eclipse.tracecompass.tmf.core.trace.ITmfContext)
     */
    @Override
    public synchronized ITmfEvent parseEvent(ITmfContext context) {
        if (context == null) {
            return null;
        }

        long rank = context.getRank();
        Map<String, Object> packetMap = null;
        PcapFile pcap = fPcapFile;
        if (pcap == null) {
            return null;
        }
        try {
            if (pcap instanceof PcapDslFile) {
                pcap.seekPacket(rank);
                packetMap = ((PcapDslFile) pcap).parseNextPacketToMap();
            }
        } catch (ClosedChannelException e) {
            /*
             * This is handled independently and happens when the user closes
             * the trace while it is being parsed. It simply stops the parsing.
             * No need to log a error.
             */
            return null;
        } catch (IOException | BadPcapFileException | BadPacketException e) {
            String message = e.getMessage();
            if (message == null) {
                message = "";
            }
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }

        if (packetMap == null) {
            return null;
        }

        // Generate an event from this packet and return it.
        return PcapDslEventFactory.createEvent(packetMap, pcap, this);
        // return PcapEventFactory.createEvent(packet, pcap, this);

    }
}