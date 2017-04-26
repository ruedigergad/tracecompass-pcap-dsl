package pcap.dsl.core.trace;

/*
 * Copyright 2017, Ruediger Gad and others (See comments "@@@@@" in source code.)
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 * The other parts of this file that were taken from existing code
 * (Marked with "@@@@@".) were also licensed under the terms of the EPL.
 * 
 */

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Map;

import org.eclipse.tracecompass.internal.pcap.core.packet.BadPacketException;
import org.eclipse.tracecompass.internal.pcap.core.trace.BadPcapFileException;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile;
import org.eclipse.tracecompass.internal.pcap.core.trace.PcapFileValues;
import org.eclipse.tracecompass.internal.pcap.core.util.ConversionHelper;

import clojure.lang.IFn;
import dsbdp.DslHelper;
import pcap.dsl.core.util.Helper;

/**
 * 
 * @author Ruediger Gad &lt;r.c.g@gmx.de&gt; and others (See comments "@@@@@" in
 *         source code.)
 *
 */
public class PcapDslFile extends PcapFile {

    public static final String PCAP_RANK = "__rank";
    public static final String PCAP_HEADER = "__header";
    public static final String PCAP_RAW_DATA = "__raw_data";

    private IFn dslFn = null;

    public PcapDslFile(Path filePath) throws BadPcapFileException, IOException {
        super(filePath);
        System.out.println("PcapDslFile(...)");
        initDslExtraction();
    }

    /*
     * (non-Javadoc)
     * 
     * @@@@@ Based on the equally named method in PcapFile:
     * 
     * @see org.eclipse.tracecompass.internal.pcap.core.trace.PcapFile#
     * parseNextPacket()
     */
    public synchronized Map<String, Object> parseNextPacketToMap()
            throws IOException, BadPcapFileException, BadPacketException {

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

        Map<String, Object> pcapPacketDataMap = null;
        if (dslFn != null && pcapPacketData.hasArray()) {
            byte[] baData = pcapPacketData.array();
            Object dslOut = dslFn.invoke(baData);

            if (dslOut instanceof Map) {
                pcapPacketDataMap = (Map<String, Object>) dslOut;
                pcapPacketDataMap.put(PCAP_HEADER, pcapPacketHeader);
                pcapPacketDataMap.put(PCAP_RANK, fCurrentRank);
                pcapPacketDataMap.put(PCAP_RAW_DATA, baData);
            }
        }

        fFileIndex.put(++fCurrentRank, fFileChannel.position());

        return pcapPacketDataMap;
    }

    private void initDslExtraction() {
        String dslExpression = Helper.getDslExpression();

        try {
            dslFn = DslHelper.generateProcessingFn(dslExpression);
            System.out.println("Successfully generated processing function.");
        } catch (Exception e) {
            System.out.println("Caught exception while generating processing function from DSL.");
            e.printStackTrace();
        }
    }

}
