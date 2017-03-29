package pcap.dsl.core.analysis;

/*******************************************************************************
 * Copyright (c) 2014 Ericsson
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Vincent Perot - Initial API and implementation
 *******************************************************************************/

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.tracecompass.tmf.core.analysis.TmfAbstractAnalysisModule;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.request.ITmfEventRequest;
import org.eclipse.tracecompass.tmf.core.request.TmfEventRequest;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimeRange;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.experiment.TmfExperiment;

import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.stream.DslPacketMapStreamBuilder;
import pcap.dsl.core.trace.PcapDslTrace;
import pcap.dsl.core.util.Helper;

/**
 * A pcap-specific analysis that parse an entire trace to find all the streams.
 *
 * @author Vincent Perot
 */
public class DslStreamListAnalysis extends TmfAbstractAnalysisModule {

    /**
     * The Stream List analysis ID.
     */
    public static final String ID = "pcap.dsl.core.analysis.stream"; //$NON-NLS-1$

    private ITmfEventRequest fRequest;
    private final Map<String, DslPacketMapStreamBuilder> fBuilders = new HashMap<>();

    /**
     * The default constructor. It initializes all variables.
     */
    public DslStreamListAnalysis() {
        super();
        System.out.println("DslStreamListAnalysis()");
    }

    @Override
    public boolean canExecute(ITmfTrace trace) {
        System.out.println("DslStreamListAnalysis.canExecute(...)");
        System.out.println("Trace: " + String.valueOf(trace));
        // Trace is Pcap
        if (trace instanceof PcapDslTrace) {
            return true;
        }

        // Trace is not a TmfExperiment
        if (!(trace instanceof TmfExperiment)) {
            return false;
        }

        // Trace is TmfExperiment. Check if it has a PcapTrace.
        TmfExperiment experiment = (TmfExperiment) trace;
        List<ITmfTrace> traces = experiment.getTraces();
        for (ITmfTrace expTrace : traces) {
            if (expTrace instanceof PcapDslTrace) {
                return true;
            }
        }

        // No Pcap :(
        return false;
    }

    @Override
    protected boolean executeAnalysis(IProgressMonitor monitor) throws TmfAnalysisException {
        System.out.println("DslStreamListAnalysis.executeAnalysis(...)");
        
        IProgressMonitor mon = (monitor == null ? new NullProgressMonitor() : monitor);
        ITmfTrace tmpTrace = getTrace();
        if (!(tmpTrace instanceof PcapDslTrace)) {
            /* This analysis was cancelled in the meantime */
            return false;
        }
        
        PcapDslTrace trace = (PcapDslTrace) tmpTrace;
        
        this.fBuilders.clear();
        Map<String, Integer> protocols = Helper.getProtocolMap(trace);
        for (Map.Entry<String, Integer> e : protocols.entrySet()) {
            this.fBuilders.put(e.getKey(), new DslPacketMapStreamBuilder(e.getKey(), e.getValue()));
        }

        ITmfEventRequest request = fRequest;
        if ((request != null) && (!request.isCompleted())) {
            request.cancel();
        }

        request = new TmfEventRequest(PcapDslEvent.class,
                TmfTimeRange.ETERNITY, 0L, ITmfEventRequest.ALL_DATA,
                ITmfEventRequest.ExecutionType.BACKGROUND) {

            @Override
            public void handleData(ITmfEvent data) {
                // Called for each event
                super.handleData(data);
                if (!(data instanceof PcapDslEvent)) {
                    return;
                }
                PcapDslEvent event = (PcapDslEvent) data;
                for (Map.Entry<String, DslPacketMapStreamBuilder> entry : fBuilders.entrySet()) {
                    entry.getValue().addEventToStream(event);
                }

            }
        };
        trace.sendRequest(request);
        fRequest = request;
        try {
            request.waitForCompletion();
        } catch (InterruptedException e) {
            // Request was canceled.
            return false;
        }

        return !mon.isCanceled() && !request.isCancelled() && !request.isFailed();

    }

    @Override
    protected void canceling() {
        ITmfEventRequest req = fRequest;
        if ((req != null) && (!req.isCompleted())) {
            req.cancel();
        }
    }

    /**
     * Getter method that returns the packet builder associated to a particular
     * protocol.
     *
     * @param protocol
     *            The specified protocol.
     * @return The builder.
     */
    public DslPacketMapStreamBuilder getBuilder(String protocol) {
        return fBuilders.get(protocol);
    }

    /**
     * Method that indicates if the analysis is still running or has finished.
     *
     * @return Whether the analysis is finished or not.
     */
    public boolean isFinished() {
        ITmfEventRequest req = fRequest;
        if (req == null) {
            return false;
        }
        return req.isCompleted();
    }

}

