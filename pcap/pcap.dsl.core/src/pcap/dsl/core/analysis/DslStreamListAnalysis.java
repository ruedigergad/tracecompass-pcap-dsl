package pcap.dsl.core.analysis;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.tracecompass.internal.tmf.pcap.core.analysis.StreamListAnalysis;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

public class DslStreamListAnalysis extends StreamListAnalysis {

    @Override
    public boolean canExecute(ITmfTrace trace) {
        System.out.println("DslStreamListAnalysis.canExecute(...)");
        boolean canExecute = super.canExecute(trace);
        System.out.println("canExecute: " + canExecute);
        return canExecute;
    }

    @Override
    protected boolean executeAnalysis(IProgressMonitor monitor) throws TmfAnalysisException {
        System.out.println("DslStreamListAnalysis.executeAnalysis(...)");
        return super.executeAnalysis(monitor);
    }
}
