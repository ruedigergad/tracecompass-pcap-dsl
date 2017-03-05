package pcap.dsl.core.aspects;

import org.eclipse.tracecompass.internal.tmf.pcap.core.event.aspect.Messages;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;

public class PcapDslProtocolAspect implements ITmfEventAspect<String> {

	public static final PcapDslProtocolAspect INSTANCE = new PcapDslProtocolAspect();

	private PcapDslProtocolAspect() {
	}

	@Override
	public String getName() {
		return Messages.PcapAspectName_Protocol;
	}

	@Override
	public String getHelpText() {
		return EMPTY_STRING;
	}

	@Override
	public String resolve(ITmfEvent event) {
		return "w";
	}

}
