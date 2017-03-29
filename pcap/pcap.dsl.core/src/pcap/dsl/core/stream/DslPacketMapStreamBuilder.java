package pcap.dsl.core.stream;

import pcap.dsl.core.event.PcapDslEvent;

public class DslPacketMapStreamBuilder {
    
    private final String protocol;
    private final int nestingLevel;
    
    public DslPacketMapStreamBuilder(String protocol, int nestingLevel) {
        this.protocol = protocol;
        this.nestingLevel = nestingLevel;
    }
    
    public void addEventToStream(PcapDslEvent event) {
        System.out.println(protocol + " " + nestingLevel + " " + String.valueOf(event));
    }

}
