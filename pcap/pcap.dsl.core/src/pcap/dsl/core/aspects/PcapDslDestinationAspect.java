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
import pcap.dsl.core.util.Helper;

/**
 * 
 * Aspect for extracting the destination addresses from {@link PcapDslEvent}
 * instances.
 * 
 * @author Ruediger Gad &lt;r.c.g@gmx.de&gt;
 *
 */
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
        return Helper.concatFields(event, "dst");
    }

}
