package pcap.dsl.core.stream;

import java.util.Map;

import pcap.dsl.core.config.Constants;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.util.Helper;

public class DslPacketMapStreamBuilder {

    private final String protocol;
    private final int nestingLevel;

    public DslPacketMapStreamBuilder(String protocol, int nestingLevel) {
        this.protocol = protocol;
        this.nestingLevel = nestingLevel;
    }

    public void addEventToStream(PcapDslEvent event) {
        Map<String, Object> nestedMap = Helper.getNestedMap(event.getPacketMap(), this.nestingLevel);
        if (this.protocol.equals(nestedMap.get(Constants.PACKET_MAP_PROTOCOL_KEY))) {
            System.out.println(protocol + " " + nestingLevel + " "
                    + String.valueOf(nestedMap.get(Constants.PACKET_MAP_SUMMARY_KEY)));
        }
    }

}
