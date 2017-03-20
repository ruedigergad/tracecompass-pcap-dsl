package pcap.dsl.core.trace;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.eclipse.tracecompass.internal.pcap.core.packet.BadPacketException;
import org.eclipse.tracecompass.internal.pcap.core.protocol.pcap.PcapPacket;
import org.eclipse.tracecompass.internal.pcap.core.trace.BadPcapFileException;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFileValues;
import org.eclipse.tracecompass.internal.pcap.core.util.ConversionHelper;

import clojure.lang.IFn;
import dsbdp.DslHelper;
import pcap.dsl.core.Activator;
import pcap.dsl.core.config.Constants;

public class PcapDslFile extends PcapFile {

    //@formatter:off
    private static final String DEFAULT_DSL_EXPRESSION = ""
            + "{:output-type :java-map\n"
            + " :rules [[dst (eth-mac-addr-str 0)]\n"
            + "         [src (eth-mac-addr-str 6)]\n"
            + "         [data [[src (ipv4-addr-str 26)]\n"
            + "                [dst (ipv4-addr-str 30)]\n"
            + "                [data [[src (int16 34)]\n"
            + "                       [dst (int16 36)]]]]]]}";
    //@formatter:on

    private IFn dslFn = null;

    public PcapDslFile(Path filePath) throws BadPcapFileException, IOException {
        super(filePath);
        System.out.println("PcapDslFile(...)");
        initDslExtraction();
    }

    /*
     * (non-Javadoc)
     * 
     * @@@@@ Taken from PcapFile:
     * 
     * @see org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile#
     * parseNextPacket()
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
        System.out.println("Included packet length: " + includedPacketLength);

        ByteBuffer pcapPacketData = ByteBuffer.allocate((int) includedPacketLength);
        pcapPacketData.clear();
        pcapPacketHeader.order(ByteOrder.BIG_ENDIAN); // Not really needed.
        fFileChannel.read(pcapPacketData);

        pcapPacketData.flip();

        if (pcapPacketData.hasArray()) {
            System.out.println("Getting byte array data...");
            byte[] baData = pcapPacketData.array();

            if (dslFn != null) {
                System.out.println("Processing byte array with DSL fn...");
                Object dslOut = dslFn.invoke(baData);
                System.out.println("DSL Output: " + String.valueOf(dslOut));
            }
        }

        fFileIndex.put(++fCurrentRank, fFileChannel.position());

        return new PcapPacket(this, null, pcapPacketHeader, pcapPacketData, fCurrentRank - 1);

    }

    private void initDslExtraction() {
        final String dslFilePath = Activator.getDefault().getPreferenceStore().getString(Constants.DSL_FILE_CONFIG_KEY);
        System.out.println("Got DSL file path from preferences: " + dslFilePath);

        String dslExpression;
        if (dslFilePath != null && !dslFilePath.isEmpty() && Files.exists(Paths.get(dslFilePath))) {
            System.out.println("Reading DSL from File: " + dslFilePath);

            try {
                dslExpression = new String(Files.readAllBytes(Paths.get(dslFilePath)), Charset.forName("UTF-8"));
            } catch (IOException e) {
                System.out.println("Caught exception while reading DSL expression file.");
                e.printStackTrace();
                System.out.println("Falling back to the default DSL expression.");
                dslExpression = DEFAULT_DSL_EXPRESSION;
            }
        } else {
            System.out.println("Invalid DSL path or file does not exist.");
            System.out.println("Using default DSL expression.");
            dslExpression = DEFAULT_DSL_EXPRESSION;
        }

        System.out.println("Using DSL expression: ");
        System.out.println(dslExpression);

        try {
            dslFn = DslHelper.generateProcessingFn(dslExpression);
            System.out.println("Successfully generated processing function.");
        } catch (Exception e) {
            System.out.println("Caught exception while generating processing function from DSL.");
            e.printStackTrace();
        }
    }

}
