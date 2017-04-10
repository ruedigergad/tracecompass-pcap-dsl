package pcap.dsl.core.trace;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

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

    public static final String PCAP_RANK = "__rank";
    public static final String PCAP_HEADER = "__header";
    //@formatter:off
    private static final String DEFAULT_DSL_EXPRESSION = ""
            + "{:output-type :java-map\n"
            + " :rules [[off (cond\n"
            + "                (= 2 (int32be 0)) 4\n"
            + "                (and\n"
            + "                  (or\n"
            + "                    (= 0 (int16 0))\n"
            + "                    (= 4 (int16 0)))\n"
            + "                  (= 1 (int16 2))\n"
            + "                  (= 0x800 (int16 14))) 16"
            + "                :default 14)]\n"
            + "         [protocol (str \"Ethernet\")]\n"
//            + "         [dst (eth-mac-addr-str 0)]\n"
//            + "         [test [[a (str \"AAA\")]"
//            + "                [b (str \"BBB\")]]]\n"
//            + "         [src (eth-mac-addr-str 6)]\n"
            + "         [data [[protocol (cond\n"
            + "                            (= 4 off) \"IPv4\"\n"
            + "                            (= 16 off) \"IPv4\"\n"
            + "                            :default (condp = (int16 12)\n"
            + "                                       0x0800 \"IPv4\"\n"
            + "                                       0x0806 \"ARP\"\n"
            + "                                       0x86DD \"IPv6\"\n"
            + "                                       (str (int16 12))))]\n"
            + "                [len (int16 (+ off 2))]\n"
            + "                [src (ipv4-addr-str (+ off 12))]\n"
            + "                [dst (ipv4-addr-str (+ off 16))]\n"
            + "                [data [[prot-id (int8 (+ off 9))]\n"
            + "                       [protocol (condp = __2_prot-id\n"
            + "                                    1 \"ICMP\"\n"
            + "                                    6 \"TCP\"\n"
            + "                                   17 \"UDP\"\n"
            + "                                   (str __2_prot-id))]\n"
            + "                       [type (condp = (int8 (+ off 20))\n"
            + "                               0 \"Echo Reply\"\n"
            + "                               3 \"Destination Unreachable\""
            + "                               8 \"Echo Request\"\n"
            + "                               (str \"Unknown ICMP Type:\" (int8 (+ off 20))))]\n"
            + "                       [seq-no (int16 (+ off 26))]"
            + "                       [summary (str \"ICMP: \" __2_type \", Seq.: \" __2_seq-no)]]]\n"
            + "                [summary (str __1_protocol \": \" __1_src \" -> \" __1_dst)]]]\n"
//            + "         [summary (str protocol \": \" src \" -> \" dst)]"
            + "]}";
//    private static final String DEFAULT_DSL_EXPRESSION = ""
//            + "{:output-type :java-map\n"
//            + " :rules [[off (cond\n"
//            + "                (= 2 (int32be 0)) 4\n"
//            + "                (and\n"
//            + "                  (or\n"
//            + "                    (= 0 (int16 0))\n"
//            + "                    (= 4 (int16 0)))\n"
//            + "                  (= 1 (int16 2))\n"
//            + "                  (= 0x800 (int16 14))) 16"
//            + "                :default 14)]\n"
//            + "         [protocol (str \"Ethernet\")]\n"
////            + "         [dst (eth-mac-addr-str 0)]\n"
////            + "         [test [[a (str \"AAA\")]"
////            + "                [b (str \"BBB\")]]]\n"
////            + "         [src (eth-mac-addr-str 6)]\n"
//            + "         [data [[protocol (cond\n"
//            + "                            (= 4 off) \"IPv4\"\n"
//            + "                            (= 16 off) \"IPv4\"\n"
//            + "                            :default (condp = (int16 12)\n"
//            + "                                       0x0800 \"IPv4\"\n"
//            + "                                       0x0806 \"ARP\"\n"
//            + "                                       0x86DD \"IPv6\"\n"
//            + "                                       (str (int16 12))))]\n"
//            + "                [len (int16 (+ off 2))]\n"
//            + "                [src (ipv4-addr-str (+ off 12))]\n"
//            + "                [dst (ipv4-addr-str (+ off 16))]\n"
//            + "                [data [[prot-id (int8 (+ off 9))]\n"
//            + "                       [protocol (condp = __2_prot-id\n"
//            + "                                    6 \"TCP\"\n"
//            + "                                   17 \"UDP\"\n"
//            + "                                   (str __2_prot-id))]\n"
//            + "                       [src (int16 (+ off 20))]\n"
//            + "                       [dst (int16 (+ off 22))]\n"
//            + "                       [summary (str __2_protocol\": \" __2_src \" -> \" __2_dst)]\n"
//            + "                       [data [[protocol (str \"NTP\")]\n"
//            + "                              [client (not= 0 (bit-and 3 (int8 (+ off 28))))]\n"
//            + "                              [server (not= 0 (bit-and 4 (int8 (+ off 28))))]\n"
//            + "                              [ref-id (ipv4-addr-str (+ off 40))]\n"
//            + "                              [ref-ts (int32be (+ off 44))]\n"
//            + "                              [orig-ts (int32be (+ off 52))]]]]]\n"
//            + "                [summary (str __1_protocol \": \" __1_src \" -> \" __1_dst)]]]\n"
////            + "         [summary (str protocol \": \" src \" -> \" dst)]"
//            + "]}";
//    private static final String DEFAULT_DSL_EXPRESSION = ""
//            + "{:output-type :java-map\n"
//            + " :rules [[off (cond\n"
//            + "                (= 2 (int32be 0)) 4\n"
//            + "                :default 14)]\n"
//            + "         [protocol (str \"Ethernet\")]\n"
//            + "         [dst (eth-mac-addr-str 0)]\n"
////            + "         [test [[a (str \"AAA\")]"
////            + "                [b (str \"BBB\")]]]\n"
//            + "         [src (eth-mac-addr-str 6)]\n"
//            + "         [data [[protocol (cond\n"
//            + "                            (= 4 off) \"IPv4\"\n"
//            + "                            :default (condp = (int16 12)\n"
//            + "                                       0x0800 \"IPv4\"\n"
//            + "                                       0x0806 \"ARP\"\n"
//            + "                                       0x86DD \"IPv6\"\n"
//            + "                                       (str (int16 12))))]\n"
//            + "                [len (int16 (+ off 2))]\n"
//            + "                [src (ipv4-addr-str (+ off 12))]\n"
//            + "                [dst (ipv4-addr-str (+ off 16))]\n"
//            + "                [data [[protocol (condp = (int8 (+ off 9))\n"
//            + "                                    6 \"TCP\"\n"
//            + "                                   17 \"UDP\"\n"
//            + "                                   (str (int8 (+ off 9))))]\n"
//            + "                       [src (int16 (+ off 20))]\n"
//            + "                       [dst (int16 (+ off 22))]\n"
//            + "                       [flags-value (int8 (+ off 33))]\n"
//            + "                       [flags (reduce-kv\n"
//            + "                                #=(eval\n"
//            + "                                    `(fn [r# k# v#]\n"
//            + "                                       (cond\n"
//            + "                                         (>\n"
//            + "                                           (bit-and\n"
//            + "                                             ~'__2_flags-value\n"
//            + "                                             (bit-shift-left 1 k#))\n"
//            + "                                           0)\n"
//            + "                                              (conj r# v#)\n"
//            + "                                       :default r#)))\n"
//            + "                                #{}\n"
//            + "                                [\"FIN\" \"SYN\" \"RST\" \"PSH\" \"ACK\" \"URG\" \"ECE\" \"CWR\"])]\n"
//            + "                       [data [[protocol (str \"STOMP\")]\n"
//            + "                              [content (ba-to-str (+ off 52) (- __1_len 52))]\n"
//            + "                              [dst (clojure.string/replace __3_content #\"(?s).*destination:(\\S*).*\" \"$1\")]\n"
//            + "                              [summary (str \"STOMP \" (first (clojure.string/split __3_content #\"\\n\")) \" -> \" __3_dst)]]]\n"
//            + "                       [summary (str __2_protocol __2_flags \": \" __2_src \" -> \" __2_dst)]]]\n"
//            + "                [summary (str __1_protocol \": \" __1_src \" -> \" __1_dst)]]]\n"
//            + "         [summary (str protocol \": \" src \" -> \" dst)]]}";
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
        if (pcapPacketData.hasArray()) {
//            System.out.println("Getting byte array data...");
            byte[] baData = pcapPacketData.array();

            if (dslFn != null) {
                //System.out.println("Processing byte array with DSL fn...");
                Object dslOut = dslFn.invoke(baData);
                //System.out.println("DSL Output: " + String.valueOf(dslOut));

                if (dslOut instanceof Map) {
                    pcapPacketDataMap = (Map<String, Object>) dslOut;
                    pcapPacketDataMap.put(PCAP_HEADER, pcapPacketHeader);
                    pcapPacketDataMap.put(PCAP_RANK, fCurrentRank);
                }
            }
        }

        fFileIndex.put(++fCurrentRank, fFileChannel.position());

        return pcapPacketDataMap;
        // return new PcapPacket(this, null, pcapPacketHeader, pcapPacketData,
        // fCurrentRank - 1);

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
