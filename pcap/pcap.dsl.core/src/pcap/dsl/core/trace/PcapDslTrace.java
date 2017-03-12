package pcap.dsl.core.trace;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;

import org.eclipse.core.resources.IResource;
import org.eclipse.tracecompass.internal.tmf.pcap.core.trace.PcapTrace;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.ITmfEventAspect;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfBaseAspects;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfTraceException;

import com.google.common.collect.ImmutableList;

import clojure.lang.IFn;
import dsbdp.DslHelper;
import pcap.dsl.core.Activator;
import pcap.dsl.core.aspects.PcapDslDestinationAspect;
import pcap.dsl.core.aspects.PcapDslProtocolAspect;
import pcap.dsl.core.aspects.PcapDslReferenceAspect;
import pcap.dsl.core.aspects.PcapDslSourceAspect;
import pcap.dsl.core.config.Constants;

public class PcapDslTrace extends PcapTrace {

    //@formatter:off
	private static final String DEFAULT_DSL_EXPRESSION = ""
	        + "{:output-type :java-map\n"
			+ " :rules [[dst (eth-mac-addr-str 16)]\n"
	        + "         [src (eth-mac-addr-str 22)]\n"
			+ "         [data [[src (ipv4-addr-str 42)]\n"
	        + "                [dst (ipv4-addr-str 46)]\n"
			+ "                [data [[src (int16 50)]\n"
	        + "                       [dst (int16 52)]]]]]]}";
	//@formatter:on

    private static final Collection<ITmfEventAspect<?>> PCAP_DSL_ASPECTS = ImmutableList.of(
            TmfBaseAspects.getTimestampAspect(), PcapDslSourceAspect.INSTANCE, PcapDslDestinationAspect.INSTANCE,
            PcapDslProtocolAspect.INSTANCE, PcapDslReferenceAspect.INSTANCE, TmfBaseAspects.getContentsAspect());

    IFn dslFn = null;
    
    @Override
    public synchronized void initTrace(IResource resource, String path, Class<? extends ITmfEvent> type)
            throws TmfTraceException {
        System.out.println("PcapDslTrace.initTrace(...)");

        initDslExtraction();

        super.initTrace(resource, path, type);
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

    @Override
    public Iterable<ITmfEventAspect<?>> getEventAspects() {
        return PCAP_DSL_ASPECTS;
    }
}
