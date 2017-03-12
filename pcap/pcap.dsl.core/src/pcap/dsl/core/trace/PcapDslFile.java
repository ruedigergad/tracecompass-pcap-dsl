package pcap.dsl.core.trace;

import java.io.IOException;
import java.nio.file.Path;

import org.eclipse.tracecompass.internal.pcap.core.trace.BadPcapFileException;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;

public class PcapDslFile extends PcapFile {

    public PcapDslFile(Path filePath) throws BadPcapFileException, IOException {
        super(filePath);
        System.out.println("PcapDslFile(...)");
    }

}
