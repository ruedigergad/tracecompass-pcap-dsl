package pcap.dsl.core.protocol;

import org.eclipse.tracecompass.internal.pcap.core.endpoint.ProtocolEndpoint;
import org.eclipse.tracecompass.internal.pcap.core.packet.Packet;

public class DslProtocolEndpoint extends ProtocolEndpoint {

    public DslProtocolEndpoint(Packet packet, boolean isSourceEndpoint) {
        super(null);
        throw new UnsupportedOperationException("DslProtocolEndpoint does not support Packet instances.");
    }

    @Override
    public int hashCode() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean equals(Object obj) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return null;
    }

}
