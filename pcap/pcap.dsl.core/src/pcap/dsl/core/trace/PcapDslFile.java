package pcap.dsl.core.trace;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;

import org.eclipse.tracecompass.internal.pcap.core.packet.BadPacketException;
import org.eclipse.tracecompass.internal.pcap.core.protocol.pcap.PcapPacket;
import org.eclipse.tracecompass.internal.pcap.core.trace.BadPcapFileException;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFileValues;
import org.eclipse.tracecompass.internal.pcap.core.util.ConversionHelper;

public class PcapDslFile extends PcapFile {

    public PcapDslFile(Path filePath) throws BadPcapFileException, IOException {
        super(filePath);
        System.out.println("PcapDslFile(...)");
    }
    
    /*
     * (non-Javadoc)
     * 
     * @@@@@ Taken from PcapFile:
     * 
     * @see org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile#parseNextPacket()
     */
    public synchronized PcapPacket parseNextPacket() throws IOException, BadPcapFileException, BadPacketException {

        System.out.println("PcapDslFile.parseNextPacket()");
        
        // Parse the packet header
        if (fFileChannel.size() - fFileChannel.position() == 0) {
            return null;
        }
        if (fFileChannel.size() - fFileChannel.position() < PcapFileValues.PACKET_HEADER_SIZE) {
            throw new BadPcapFileException("A pcap header is invalid."); //$NON-NLS-1$
        }

        ByteBuffer pcapPacketHeader = ByteBuffer.allocate(PcapFileValues.PACKET_HEADER_SIZE);
        pcapPacketHeader.clear();
        pcapPacketHeader.order(fByteOrder);

        fFileChannel.read(pcapPacketHeader);

        pcapPacketHeader.flip();
        pcapPacketHeader.position(PcapFileValues.INCLUDED_LENGTH_POSITION);
        long includedPacketLength = ConversionHelper.unsignedIntToLong(pcapPacketHeader.getInt());

        if (fFileChannel.size() - fFileChannel.position() < includedPacketLength) {
            throw new BadPcapFileException("A packet header is invalid."); //$NON-NLS-1$
        }

        if (includedPacketLength > Integer.MAX_VALUE) {
            throw new BadPacketException("Packets that are bigger than 2^31-1 bytes are not supported."); //$NON-NLS-1$
        }

        ByteBuffer pcapPacketData = ByteBuffer.allocate((int) includedPacketLength);
        pcapPacketData.clear();
        pcapPacketHeader.order(ByteOrder.BIG_ENDIAN); // Not really needed.
        fFileChannel.read(pcapPacketData);

        pcapPacketData.flip();

        fFileIndex.put(++fCurrentRank, fFileChannel.position());

        return new PcapPacket(this, null, pcapPacketHeader, pcapPacketData, fCurrentRank - 1);

    }

}
