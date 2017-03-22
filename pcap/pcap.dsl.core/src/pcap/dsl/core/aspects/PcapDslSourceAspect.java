package pcap.dsl.core.aspects;

import java.util.Map;

import org.eclipse.tracecompass.internal.tmf.pcap.core.event.aspect.Messages;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;

import pcap.dsl.core.event.PcapDslEvent;

public class PcapDslSourceAspect implements ITmfEventAspect<String> {

    public static final PcapDslSourceAspect INSTANCE = new PcapDslSourceAspect();

    private PcapDslSourceAspect() {
    }

    @Override
    public String getName() {
        return Messages.PcapAspectName_Source;
    }

    @Override
    public String getHelpText() {
        return EMPTY_STRING;
    }

    @Override
    public String resolve(ITmfEvent ev) {
        return AspectMapHelper.concatFields(ev, "src");
    }

}
