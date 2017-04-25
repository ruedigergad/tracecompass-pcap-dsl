package pcap.dsl.core.aspects;

import org.eclipse.tracecompass.internal.tmf.pcap.core.event.aspect.Messages;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;

/*
 * Copyright 2017, Ruediger Gad
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 */

import pcap.dsl.core.event.PcapDslEvent;

/**
 * 
 * Aspect for extracting the destination addresses from {@link PcapDslEvent}
 * instances.
 * 
 * @author Ruediger Gad &lt;r.c.g@gmx.de&gt;
 *
 */
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
