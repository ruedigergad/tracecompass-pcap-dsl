package pcap.dsl.core.event;

import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.TmfEventField;

import pcap.dsl.core.config.Constants;

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
