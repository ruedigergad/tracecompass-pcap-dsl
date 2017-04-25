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
import org.eclipse.tracecompass.tmf.core.event.TmfEventField;

import pcap.dsl.core.config.Constants;

/**
 * Event field for {@link PcapDslEvent}. The data is contained in the map
 * associated to the corresponding event.
 * 
 * @author &lt;r.c.g@gmx.de&gt;
 *
 */
public class PcapDslEventField extends TmfEventField {

    private final Map<String, Object> content;

    public PcapDslEventField(String name, Object value, ITmfEventField[] fields, Map<String, Object> content) {
        super(name, value, fields);
        this.content = content;
    }

    public String toString() {
        if (content.containsKey(Constants.PACKET_MAP_SUMMARY_KEY)) {
            return String.valueOf(content.get(Constants.PACKET_MAP_SUMMARY_KEY));
        }

        return super.toString();
    }

}
