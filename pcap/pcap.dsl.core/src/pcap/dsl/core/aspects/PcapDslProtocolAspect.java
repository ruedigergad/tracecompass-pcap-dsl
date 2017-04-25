package pcap.dsl.core.aspects;

/*
 * Copyright 2017, Ruediger Gad
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 */

import org.eclipse.tracecompass.internal.tmf.pcap.core.event.aspect.Messages;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;

import pcap.dsl.core.event.PcapDslEvent;

/**
 * 
 * Aspect for extracting the protocol names from {@link PcapDslEvent}
 * instances.
 * 
 * @author Ruediger Gad &lt;r.c.g@gmx.de&gt;
 *
 */
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
