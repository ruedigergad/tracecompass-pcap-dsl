package pcap.dsl.core.util;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.request.ITmfEventRequest;
import org.eclipse.tracecompass.tmf.core.request.TmfEventRequest;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimeRange;

import pcap.dsl.core.Activator;
import pcap.dsl.core.config.Constants;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.trace.PcapDslTrace;

public class Helper {

    //@formatter:off
//  private static final String DEFAULT_DSL_EXPRESSION = ""
//          + "{:output-type :java-map\n"
//          + " :rules [[off (cond\n"
//          + "                (= 2 (int32be 0)) 4\n"
//          + "                (and\n"
//          + "                  (or\n"
//          + "                    (= 0 (int16 0))\n"
//          + "                    (= 4 (int16 0)))\n"
//          + "                  (= 1 (int16 2))\n"
//          + "                  (= 0x800 (int16 14))) 16"
//          + "                :default 14)]\n"
//          + "         [protocol (str \"Ethernet\")]\n"
////          + "         [dst (eth-mac-addr-str 0)]\n"
////          + "         [test [[a (str \"AAA\")]"
////          + "                [b (str \"BBB\")]]]\n"
////          + "         [src (eth-mac-addr-str 6)]\n"
//          + "         [data [[protocol (cond\n"
//          + "                            (= 4 off) \"IPv4\"\n"
//          + "                            (= 16 off) \"IPv4\"\n"
//          + "                            :default (condp = (int16 12)\n"
//          + "                                       0x0800 \"IPv4\"\n"
//          + "                                       0x0806 \"ARP\"\n"
//          + "                                       0x86DD \"IPv6\"\n"
//          + "                                       (str (int16 12))))]\n"
//          + "                [len (int16 (+ off 2))]\n"
//          + "                [src (ipv4-addr-str (+ off 12))]\n"
//          + "                [dst (ipv4-addr-str (+ off 16))]\n"
//          + "                [data [[prot-id (int8 (+ off 9))]\n"
//          + "                       [protocol (condp = __2_prot-id\n"
//          + "                                    1 \"ICMP\"\n"
//          + "                                    6 \"TCP\"\n"
//          + "                                   17 \"UDP\"\n"
//          + "                                   (str __2_prot-id))]\n"
//          + "                       [type (condp = (int8 (+ off 20))\n"
//          + "                               0 \"Echo Reply\"\n"
//          + "                               3 \"Destination Unreachable\""
//          + "                               8 \"Echo Request\"\n"
//          + "                               (str \"Unknown ICMP Type:\" (int8 (+ off 20))))]\n"
//          + "                       [seq-no (int16 (+ off 26))]"
//          + "                       [summary (str \"ICMP: \" __2_type \", Seq.: \" __2_seq-no)]]]\n"
//          + "                [summary (str __1_protocol \": \" __1_src \" -> \" __1_dst)]]]\n"
////          + "         [summary (str protocol \": \" src \" -> \" dst)]"
//          + "]}";
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
          + "         [dst (eth-mac-addr-str 0)]\n"
          + "         [src (eth-mac-addr-str 6)]\n"
          + "         [data [[protocol (str \"IPv4\")]\n"
          + "                [len (int16 (+ off 2))]\n"
          + "                [src (ipv4-addr-str (+ off 12))]\n"
          + "                [dst (ipv4-addr-str (+ off 16))]\n"
          + "                [protocol-id (int8 (+ off 9))]\n"
          + "                [data [(= 17 __1_protocol-id)\n"
          + "                         [[protocol (str \"UDP\")]\n"
          + "                          [src (int16 (+ off 20))]\n"
          + "                          [dst (int16 (+ off 22))]\n"
          + "                          [summary (str __2_protocol \": \" __2_src \" -> \" __2_dst)]]\n"
          + "                       (= 6 __1_protocol-id)\n"
          + "                         [[protocol (str \"TCP\")]\n"
          + "                          [src (int16 (+ off 20))]\n"
          + "                          [dst (int16 (+ off 22))]\n"
          + "                          [flags-value (int8 (+ off 33))]\n"
          + "                          [flags (reduce-kv\n"
          + "                                   #=(eval\n"
          + "                                       `(fn [r# k# v#]\n"
          + "                                          (cond\n (> (bit-and ~'__2_flags-value (bit-shift-left 1 k#)) 0)\n"
          + "                                            (conj r# v#)\n"
          + "                                          :default r#)))\n"
          + "                                   #{}\n"
          + "                                   [\"FIN\" \"SYN\" \"RST\" \"PSH\" \"ACK\" \"URG\" \"ECE\" \"CWR\"])]\n"
          + "                          [summary (str __2_protocol __2_flags \": \" __2_src \" -> \" __2_dst)]]\n"
          + "                       (= 1 __1_protocol-id)\n"
          + "                         [[protocol (str \"ICMP\")]\n"
          + "                          [type (condp = (int8 (+ off 20))\n"
          + "                                  0 \"Echo Reply\"\n"
          + "                                  3 \"Destination Unreachable\"\n"
          + "                                  8 \"Echo Request\"\n"
          + "                                 (str \"Unknown ICMP Type:\" (int8 (+ off 20))))]\n"
          + "                          [seq-no (int16 (+ off 26))]\n"
          + "                          [summary (str \"ICMP: \" __2_type \", Seq.: \" __2_seq-no)]]]]\n"
          + "                [summary (str __1_protocol \": \" __1_src \" -> \" __1_dst)]]]\n"
          + "         [summary (str protocol \": \" src \" -> \" dst)]"
          + "]}";
//+ "                       [data [[protocol (str \"NTP\")]\n"
//+ "                              [client (not= 0 (bit-and 3 (int8 (+ off 28))))]\n"
//+ "                              [server (not= 0 (bit-and 4 (int8 (+ off 28))))]\n"
//+ "                              [ref-id (ipv4-addr-str (+ off 40))]\n"
//+ "                              [ref-ts (ntp-timestamp-str (+ off 44))]\n"
//+ "                              [orig-ts (ntp-timestamp-str (+ off 52))]]]]]\n"
//  private static final String DEFAULT_DSL_EXPRESSION = ""
//          + "{:output-type :java-map\n"
//          + " :rules [[off (cond\n"
//          + "                (= 2 (int32be 0)) 4\n"
//          + "                :default 14)]\n"
//          + "         [protocol (str \"Ethernet\")]\n"
//          + "         [dst (eth-mac-addr-str 0)]\n"
////          + "         [test [[a (str \"AAA\")]"
////          + "                [b (str \"BBB\")]]]\n"
//          + "         [src (eth-mac-addr-str 6)]\n"
//          + "         [data [[protocol (cond\n"
//          + "                            (= 4 off) \"IPv4\"\n"
//          + "                            :default (condp = (int16 12)\n"
//          + "                                       0x0800 \"IPv4\"\n"
//          + "                                       0x0806 \"ARP\"\n"
//          + "                                       0x86DD \"IPv6\"\n"
//          + "                                       (str (int16 12))))]\n"
//          + "                [len (int16 (+ off 2))]\n"
//          + "                [src (ipv4-addr-str (+ off 12))]\n"
//          + "                [dst (ipv4-addr-str (+ off 16))]\n"
//          + "                [data [[protocol (condp = (int8 (+ off 9))\n"
//          + "                                    6 \"TCP\"\n"
//          + "                                   17 \"UDP\"\n"
//          + "                                   (str (int8 (+ off 9))))]\n"
//          + "                       [src (int16 (+ off 20))]\n"
//          + "                       [dst (int16 (+ off 22))]\n"
//          + "                       [flags-value (int8 (+ off 33))]\n"
//          + "                       [flags (reduce-kv\n"
//          + "                                #=(eval\n"
//          + "                                    `(fn [r# k# v#]\n"
//          + "                                       (cond\n"
//          + "                                         (>\n"
//          + "                                           (bit-and\n"
//          + "                                             ~'__2_flags-value\n"
//          + "                                             (bit-shift-left 1 k#))\n"
//          + "                                           0)\n"
//          + "                                              (conj r# v#)\n"
//          + "                                       :default r#)))\n"
//          + "                                #{}\n"
//          + "                                [\"FIN\" \"SYN\" \"RST\" \"PSH\" \"ACK\" \"URG\" \"ECE\" \"CWR\"])]\n"
//          + "                       [data [[protocol (str \"STOMP\")]\n"
//          + "                              [content (ba-to-str (+ off 52) (- __1_len 52))]\n"
//          + "                              [dst (clojure.string/replace __3_content #\"(?s).*destination:(\\S*).*\" \"$1\")]\n"
//          + "                              [summary (str \"STOMP \" (first (clojure.string/split __3_content #\"\\n\")) \" -> \" __3_dst)]]]\n"
//          + "                       [summary (str __2_protocol __2_flags \": \" __2_src \" -> \" __2_dst)]]]\n"
//          + "                [summary (str __1_protocol \": \" __1_src \" -> \" __1_dst)]]]\n"
//          + "         [summary (str protocol \": \" src \" -> \" dst)]]}";
  //@formatter:on
    
    private Helper() {
        // No instances allowed of Helper class.
    }

    public static Map<String, Object> getNestedMap(Map<String, Object> parentMap, int nestingLevel) {
        Map<String, Object> tmpMap = parentMap;
        int currentNestingLevel = 0;

        while (tmpMap != null && currentNestingLevel < nestingLevel) {
            if (tmpMap.get(Constants.PACKET_MAP_DATA_KEY) instanceof Map<?, ?>) {
                tmpMap = (Map<String, Object>) tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                currentNestingLevel++;
            } else {
                tmpMap = null;
            }
        }

        return tmpMap;
    }

    public static Map<String, Integer> getProtocolMap(PcapDslTrace trace) {
        Map<String, Integer> protocolMap = new HashMap<>();

        if (trace != null) {
            // ITmfEventRequest request = fRequest;
            // if ((request != null) && (!request.isCompleted())) {
            // request.cancel();
            // }

            ITmfEventRequest request = new TmfEventRequest(PcapDslEvent.class, TmfTimeRange.ETERNITY, 0L,
                    ITmfEventRequest.ALL_DATA, ITmfEventRequest.ExecutionType.BACKGROUND) {

                @Override
                public void handleData(ITmfEvent data) {
                    // Called for each event
                    super.handleData(data);
                    if (!(data instanceof PcapDslEvent)) {
                        return;
                    }
                    PcapDslEvent event = (PcapDslEvent) data;

                    int nestingLevel = 0;
                    Map<String, Object> tmpMap = event.getPacketMap();
                    while (tmpMap != null) {
                        Object proto = tmpMap.get(Constants.PACKET_MAP_PROTOCOL_KEY);
                        if (proto instanceof String && !protocolMap.containsKey(proto)) {
                            protocolMap.put((String) proto, nestingLevel);
                        }

                        Object tmpData = tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                        if (tmpData instanceof Map<?, ?>) {
                            tmpMap = (Map<String, Object>) tmpData;
                        } else {
                            tmpMap = null;
                        }
                        nestingLevel++;
                    }
                }
            };
            trace.sendRequest(request);

            try {
                request.waitForCompletion();
            } catch (InterruptedException e) {
                // Request was canceled.
                return new HashMap<String, Integer>();
            }

            System.out.println("Got protocolMap: " + String.valueOf(protocolMap));
        }

        return protocolMap;
    }

    public static String getMergedString(Map<String, Object> packetMap, String key, int nestingLevel) {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> tmpMap = packetMap;
        int currentNestingLevel = 0;

        while (tmpMap != null) {
            if (tmpMap.containsKey(key)) {
                sb.append(tmpMap.get(key));
            }

            if (tmpMap.get(Constants.PACKET_MAP_DATA_KEY) instanceof Map<?, ?> && currentNestingLevel < nestingLevel) {
                sb.append(Constants.SEPARATOR);
                tmpMap = (Map<String, Object>) tmpMap.get(Constants.PACKET_MAP_DATA_KEY);
                currentNestingLevel++;
            } else {
                tmpMap = null;
            }
        }

        return sb.toString();
    }
    
    public static String getDslExpression() {
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
        
        return dslExpression;
    }
}
