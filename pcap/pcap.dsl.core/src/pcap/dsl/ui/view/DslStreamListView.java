package pcap.dsl.ui.view;

/*******************************************************************************
 * Copyright (c) 2014, 2015 Ericsson
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Vincent Perot - Initial API and implementation
 *   Patrick Tasse - Support aspect filters
 *******************************************************************************/

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.tracecompass.internal.tmf.pcap.core.event.TmfPacketStream;
import org.eclipse.tracecompass.internal.tmf.pcap.ui.Activator;
import org.eclipse.tracecompass.internal.tmf.pcap.ui.stream.Messages;
import org.eclipse.tracecompass.tmf.core.signal.TmfSignalHandler;
import org.eclipse.tracecompass.tmf.core.signal.TmfTraceClosedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfTraceOpenedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfTraceSelectedSignal;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;
import org.eclipse.tracecompass.tmf.ui.views.TmfView;

import pcap.dsl.core.analysis.DslStreamListAnalysis;
import pcap.dsl.core.stream.DslPacketMapStream;
import pcap.dsl.core.stream.DslPacketMapStreamBuilder;
import pcap.dsl.core.trace.PcapDslTrace;
import pcap.dsl.core.util.Helper;

/**
 * Class that represents the Stream List View. Such a view lists all the
 * available streams from the current experiment. <br>
 * <br>
 * TODO Switch to TmfUiRefreshHandler once the behavior is fixed
 *
 * FIXME analysis is leaking ressource. Someone I will not name told me not to
 * worry about it since AnalysisModule will not be autocloseable later.
 *
 * @author Vincent Perot
 */
public class DslStreamListView extends TmfView {

    /**
     * The Stream List View ID.
     */
    public static final String ID = "pcap.dsl.ui.view.stream.list";

    private static final String[] COLUMN_NAMES = { Messages.StreamListView_ID, Messages.StreamListView_EndpointA,
            Messages.StreamListView_EndpointB, Messages.StreamListView_TotalPackets, Messages.StreamListView_TotalBytes,
            Messages.StreamListView_PacketsAtoB, Messages.StreamListView_BytesAtoB, Messages.StreamListView_PacketsBtoA,
            Messages.StreamListView_BytesBtoA, Messages.StreamListView_StartTime, Messages.StreamListView_StopTime,
            Messages.StreamListView_Duration, Messages.StreamListView_BPSAtoB, Messages.StreamListView_BPSBtoA };

    private static final int[] COLUMN_SIZES = { 75, 350, 350, 110, 110, 110, 110, 110, 110, 180, 180, 110, 110, 110 };

    private static final String KEY_PROTOCOL = "$protocol$"; //$NON-NLS-1$
    private static final String KEY_STREAM = "$stream$"; //$NON-NLS-1$

    private static final String EMPTY_STRING = ""; //$NON-NLS-1$

    private static final long WAIT_TIME = 1000;

    private CTabFolder fTabFolder;
    private Map<String, Table> fTableMap;

    private TmfPacketStream fCurrentStream;
    private PcapDslTrace fCurrentTrace;

    private volatile boolean fStopThread;

    private boolean contentReady;

    private Map<String, Integer> fProtocolMap;

    /**
     * Constructor of the StreamListView class.
     */
    public DslStreamListView() {
        super(ID);
        System.out.println("DslStreamListView...");
    }

    /**
     * Handler called when an trace is opened.
     *
     * @param signal
     *            Contains the information about the selection.
     */
    @TmfSignalHandler
    public void traceOpened(TmfTraceOpenedSignal signal) {
        System.out.println("DslStreamListView.traceOpened()");
        Object currentTrace = signal.getTrace();
        System.out.println("Trace type: " + currentTrace.getClass().getName());

        if (!(currentTrace instanceof PcapDslTrace)) {
            throw new UnsupportedOperationException("DslStreamListView only supports PcapDslTrace instances.");
        }

        fCurrentTrace = (PcapDslTrace) currentTrace;
        createContent();
        resetView();
        queryAnalysis();
    }

    /**
     * Handler called when an trace is closed. Checks if the trace is the
     * current trace and update the view accordingly.
     *
     * @param signal
     *            Contains the information about the selection.
     */
    @TmfSignalHandler
    public void traceClosed(TmfTraceClosedSignal signal) {
        if (fCurrentTrace == signal.getTrace()) {
            fCurrentTrace = null;
            resetView();
        }
    }

    /**
     * Handler called when an trace is selected. Checks if the trace has changed
     * and requests the selected trace if it has not yet been cached.
     *
     * @param signal
     *            Contains the information about the selection.
     */
    @TmfSignalHandler
    public void traceSelected(TmfTraceSelectedSignal signal) {
        Object newTrace = signal.getTrace();
        if (fCurrentTrace != newTrace && (newTrace instanceof PcapDslTrace)) {
            fCurrentTrace = (PcapDslTrace) newTrace;
            createContent();
            resetView();
            queryAnalysis();
        }
    }

    private void queryAnalysis() {
        Thread thread = new Thread(new Runnable() {

            @Override
            public void run() {
                ITmfTrace trace = fCurrentTrace;
                if (trace == null) {
                    return;
                }
                DslStreamListAnalysis analysis = TmfTraceUtils.getAnalysisModuleOfClass(trace,
                        DslStreamListAnalysis.class, DslStreamListAnalysis.ID);
                if (analysis == null) {
                    return;
                }
                while (!analysis.isFinished() && !fStopThread) {
                    updateUI();
                    try {
                        Thread.sleep(WAIT_TIME);
                    } catch (InterruptedException e) {
                        String message = e.getMessage();
                        if (message == null) {
                            message = EMPTY_STRING;
                        }
                        Activator.logError(message, e);
                        return;
                    }
                }
                // Update UI one more time (daft punk)
                if (!fStopThread) {
                    updateUI();
                }
            }
        });

        fStopThread = false;
        thread.start();
    }

    private void resetView() {

        // Stop thread if needed
        fStopThread = true;

        // Remove all content in tables
        final Display display = Display.getDefault();
        if (display == null || display.isDisposed()) {
            return;
        }
        display.asyncExec(new Runnable() {

            @Override
            public void run() {
                if (display.isDisposed()) {
                    return;
                }
                Map<String, Table> tableMap = fTableMap;
                if (tableMap == null) {
                    return;
                }
                for (Table table : tableMap.values()) {
                    if (!table.isDisposed()) {
                        table.removeAll();
                    }
                }
            }
        });
    }

    private void updateUI() {
        final Display display = Display.getDefault();
        if (display == null || display.isDisposed()) {
            return;
        }
        display.asyncExec(new Runnable() {

            @Override
            public void run() {
                if (display.isDisposed()) {
                    return;
                }
                ITmfTrace trace = fCurrentTrace;
                if (trace == null) {
                    return;
                }

                DslStreamListAnalysis analysis = TmfTraceUtils.getAnalysisModuleOfClass(trace,
                        DslStreamListAnalysis.class, DslStreamListAnalysis.ID);
                if (analysis == null) {
                    return;
                }

                Map<String, Table> tables = fTableMap;
                if (tables == null) {
                    return;
                }
                for (Entry<String, Table> protocolEntry : tables.entrySet()) {
                    String protocol = protocolEntry.getKey();
                    DslPacketMapStreamBuilder builder = analysis.getBuilder(protocol);
                    Table table = protocolEntry.getValue();
                    if (builder != null && !(table.isDisposed())) {
                        for (DslPacketMapStream stream : builder.getStreams()) {

                            TableItem item;
                            if (stream.getID() < table.getItemCount()) {
                                item = table.getItem(stream.getID());
                            } else {
                                item = new TableItem(table, SWT.NONE);
                            }
                            item.setText(0, String.valueOf(stream.getID()));
                            item.setText(1, String.valueOf(stream.getAAddress()));
                            item.setText(2, String.valueOf(stream.getBAddress()));
                            item.setText(3, String.valueOf(stream.getNbPackets()));
                            item.setText(4, String.valueOf(stream.getNbBytes()));
                            item.setText(5, String.valueOf(stream.getNbPacketsAtoB()));
                            item.setText(6, String.valueOf(stream.getNbBytesAtoB()));
                            item.setText(7, String.valueOf(stream.getNbPacketsBtoA()));
                            item.setText(8, String.valueOf(stream.getNbBytesBtoA()));
                            item.setText(9, String.valueOf(stream.getStartTime()));
                            item.setText(10, String.valueOf(stream.getStopTime()));
                            item.setText(11, String.format("%.3f", stream.getDuration())); // $NON-NLS-1$
                            item.setText(12, String.format("%.3f", stream.getBPSAtoB()));
                            // $NON-NLS-1$
                            item.setText(13, String.format("%.3f", stream.getBPSBtoA()));
                            // $NON-NLS-1$
//                            item.setData(KEY_STREAM, stream);
                        }
                    }
                }
            }

        });
    }

    @Override
    public void createPartControl(Composite parent) {
        System.out.println("DslStreamListView.createPartControl(...)");
        System.out.println("fCurrentTrace: " + String.valueOf(this.fCurrentTrace));

        fTabFolder = new CTabFolder(parent, SWT.NONE);
    }

    private void createContent() {
        System.out.println("DslStreamListView.createContent()");
        synchronized (this) {
            if (this.contentReady) {
                return;
            }
            this.contentReady = true;
        }
        System.out.println("Creating content...");

        this.fProtocolMap = Helper.getProtocolMap(fCurrentTrace);

        // Initialize
        final Map<String, Table> tables = new HashMap<>();
        fTableMap = tables;

        fCurrentStream = null;

        // Add a tab folder

        // fTabFolder.addSelectionListener(new SelectionAdapter() {
        //
        // @Override
        // public void widgetSelected(SelectionEvent e) {
        // if (e == null) {
        // return;
        // }
        // TmfPcapProtocol protocol = (TmfPcapProtocol)
        // e.item.getData(KEY_PROTOCOL);
        // final Table table = tables.get(protocol);
        // if (table != null) {
        // table.deselectAll();
        // }
        // fCurrentStream = null;
        // }
        //
        // });

        // Add items and tables for each protocol
        for (String protocol : fProtocolMap.keySet()) {
            CTabItem item = new CTabItem(fTabFolder, SWT.NONE);
            item.setText(protocol);
            item.setData(KEY_PROTOCOL, protocol);
            Table table = new Table(fTabFolder, SWT.NONE);
            table.setHeaderVisible(true);
            table.setLinesVisible(true);

            // Add columns to table
            for (int i = 0; i < COLUMN_NAMES.length || i < COLUMN_SIZES.length; i++) {
                TableColumn column = new TableColumn(table, SWT.NONE);
                column.setText(COLUMN_NAMES[i]);
                column.setWidth(COLUMN_SIZES[i]);
            }
            item.setControl(table);
            table.addSelectionListener(new SelectionAdapter() {

                @Override
                public void widgetSelected(SelectionEvent e) {
                    if (e == null) {
                        return;
                    }
                    fCurrentStream = (TmfPacketStream) e.item.getData(KEY_STREAM);
                }

            });

            tables.put(protocol, table);

            // // Add right click menu
            // Menu menu = new Menu(table);
            // MenuItem menuItem = new MenuItem(menu, SWT.PUSH);
            // menuItem.setText(Messages.StreamListView_FollowStream);
            // menuItem.addListener(SWT.Selection, new Listener() {
            //
            // @Override
            // public void handleEvent(Event event) {
            // TmfSignal signal = new TmfPacketStreamSelectedSignal(this, 0,
            // fCurrentStream);
            // TmfSignalManager.dispatchSignal(signal);
            // }
            // });
            // menuItem = new MenuItem(menu, SWT.PUSH);
            // menuItem.setText(Messages.StreamListView_Clear);
            // menuItem.addListener(SWT.Selection, new Listener() {
            //
            // @Override
            // public void handleEvent(Event event) {
            // TmfSignal signal = new TmfPacketStreamSelectedSignal(this, 0,
            // null);
            // TmfSignalManager.dispatchSignal(signal);
            //
            // }
            // });
            // menuItem = new MenuItem(menu, SWT.PUSH);
            // menuItem.setText(Messages.StreamListView_ExtractAsFilter);
            // menuItem.addListener(SWT.Selection, new Listener() {
            //
            // @Override
            // public void handleEvent(Event event) {
            // // Generate filter.
            // ITmfFilterTreeNode filter = generateFilter();
            //
            // // Update view and XML
            // updateFilters(filter);
            //
            // }
            //
            // private void updateFilters(ITmfFilterTreeNode filter) {
            // if (filter == null) {
            // return;
            // }
            //
            // // Update XML
            // List<ITmfFilterTreeNode> filters =
            // Lists.newArrayList(FilterManager.getSavedFilters());
            // boolean newFilter = true;
            // for (ITmfFilterTreeNode savedFilter : filters) {
            // // Use toString(explicit) equality because equals()
            // // is not implemented
            // if (savedFilter.toString(true).equals(filter.toString(true))) {
            // newFilter = false;
            // break;
            // }
            // }
            // if (newFilter) {
            // filters.add(filter);
            // FilterManager.setSavedFilters(filters.toArray(new
            // ITmfFilterTreeNode[filters.size()]));
            // }
            //
            // // Update Filter View
            // try {
            // final IWorkbench wb = PlatformUI.getWorkbench();
            // final IWorkbenchPage activePage =
            // wb.getActiveWorkbenchWindow().getActivePage();
            // IViewPart view = activePage.showView(FilterView.ID);
            // FilterView filterView = (FilterView) view;
            // filterView.addFilter(filter);
            // } catch (final PartInitException e) {
            // TraceUtils.displayErrorMsg(Messages.StreamListView_ExtractAsFilter,
            // "Error opening view " + FilterView.ID + e.getMessage());
            // //$NON-NLS-1$
            // Activator.logError("Error opening view " + FilterView.ID, e);
            // //$NON-NLS-1$
            // return;
            // }
            //
            // }
            //
            // private ITmfFilterTreeNode generateFilter() {
            // TmfPacketStream stream = fCurrentStream;
            // if (stream == null) {
            // return null;
            // }
            //
            // // First stage - root
            // String name = Messages.StreamListView_FilterName_Stream + ' '
            // + stream.getProtocol().getShortName() + ' ' +
            // stream.getFirstEndpoint() + " <--> " //$NON-NLS-1$
            // + stream.getSecondEndpoint();
            // TmfFilterNode root = new TmfFilterNode(name);
            //
            // // Second stage - and
            // TmfFilterAndNode and = new TmfFilterAndNode(root);
            //
            // // Third stage - protocol + or
            // TmfFilterContainsNode protocolFilter = new
            // TmfFilterContainsNode(and);
            // protocolFilter.setEventAspect(
            // TmfBaseAspects.getContentsAspect().forField(stream.getProtocol().getName()));
            // protocolFilter.setTraceTypeId(TmfFilterAspectNode.BASE_ASPECT_ID);
            // protocolFilter.setValue(EMPTY_STRING);
            // TmfFilterOrNode or = new TmfFilterOrNode(and);
            //
            // // Fourth stage - and
            // TmfFilterAndNode andA = new TmfFilterAndNode(or);
            // TmfFilterAndNode andB = new TmfFilterAndNode(or);
            //
            // // Fourth stage - endpoints
            // TmfFilterContainsNode endpointAAndA = new
            // TmfFilterContainsNode(andA);
            // endpointAAndA.setEventAspect(PcapSourceAspect.INSTANCE);
            // endpointAAndA.setTraceTypeId(PcapTrace.TRACE_TYPE_ID);
            // endpointAAndA.setValue(stream.getFirstEndpoint());
            // TmfFilterContainsNode endpointBAndA = new
            // TmfFilterContainsNode(andA);
            // endpointBAndA.setEventAspect(PcapDestinationAspect.INSTANCE);
            // endpointBAndA.setTraceTypeId(PcapTrace.TRACE_TYPE_ID);
            // endpointBAndA.setValue(stream.getSecondEndpoint());
            // TmfFilterContainsNode endpointAAndB = new
            // TmfFilterContainsNode(andB);
            // endpointAAndB.setEventAspect(PcapSourceAspect.INSTANCE);
            // endpointAAndB.setTraceTypeId(PcapTrace.TRACE_TYPE_ID);
            // endpointAAndB.setValue(stream.getSecondEndpoint());
            // TmfFilterContainsNode endpointBAndB = new
            // TmfFilterContainsNode(andB);
            // endpointBAndB.setEventAspect(PcapDestinationAspect.INSTANCE);
            // endpointBAndB.setTraceTypeId(PcapTrace.TRACE_TYPE_ID);
            // endpointBAndB.setValue(stream.getFirstEndpoint());
            //
            // return root;
            // }
            // });
            // table.setMenu(menu);

        }

        // Ask the analysis for data.
        queryAnalysis();
    }

    @Override
    public void setFocus() {
        CTabFolder tabFolder = fTabFolder;
        if (tabFolder != null && !(tabFolder.isDisposed())) {
            tabFolder.setFocus();
        }
    }

}
