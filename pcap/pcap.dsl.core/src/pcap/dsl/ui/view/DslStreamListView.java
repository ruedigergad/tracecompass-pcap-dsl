package pcap.dsl.ui.view;

import org.eclipse.tracecompass.internal.tmf.pcap.ui.stream.StreamListView;

public class DslStreamListView extends StreamListView {

    public static final String ID = "pcap.dsl.ui.view.stream.list";

    public DslStreamListView() {
        super(ID);
        System.out.println("DslStreamListView()");
    }
}
