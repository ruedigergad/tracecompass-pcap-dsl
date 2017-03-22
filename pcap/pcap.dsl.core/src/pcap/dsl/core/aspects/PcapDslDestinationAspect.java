package pcap.dsl.core.aspects;

import org.eclipse.tracecompass.internal.tmf.pcap.core.event.aspect.Messages;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;

public class PcapDslDestinationAspect implements ITmfEventAspect<String> {

	public static final PcapDslDestinationAspect INSTANCE = new PcapDslDestinationAspect();

	private PcapDslDestinationAspect() {
	}

	@Override
	public String getName() {
		return Messages.PcapAspectName_Destination;
	}

	@Override
	public String getHelpText() {
		return EMPTY_STRING;
	}

	@Override
	public String resolve(ITmfEvent event) {
		return AspectMapHelper.concatFields(event, "dst");
	}

}
