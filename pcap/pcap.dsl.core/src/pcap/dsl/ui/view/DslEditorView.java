package pcap.dsl.ui.view;

import java.util.Map;

import org.eclipse.jface.text.Document;
import org.eclipse.jface.text.IDocument;
import org.eclipse.jface.text.ITextListener;
import org.eclipse.jface.text.Position;
import org.eclipse.jface.text.TextEvent;
import org.eclipse.jface.text.source.Annotation;
import org.eclipse.jface.text.source.CompositeRuler;
import org.eclipse.jface.text.source.LineNumberRulerColumn;
import org.eclipse.jface.text.source.OverviewRuler;
import org.eclipse.jface.text.source.projection.ProjectionAnnotation;
import org.eclipse.jface.text.source.projection.ProjectionAnnotationModel;
import org.eclipse.jface.text.source.projection.ProjectionSupport;
import org.eclipse.jface.text.source.projection.ProjectionViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.signal.TmfEventSelectedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfSignalHandler;
import org.eclipse.tracecompass.tmf.ui.views.TmfView;
import org.eclipse.ui.internal.editors.text.EditorsPlugin;
import org.eclipse.ui.texteditor.DefaultMarkerAnnotationAccess;

import clojure.lang.IFn;
import dsbdp.DslHelper;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.trace.PcapDslFile;
import pcap.dsl.core.util.Helper;

public class DslEditorView extends TmfView {

    public static final String ID = "pcap.dsl.core.DslEditorView";

    private static final int RULER_WIDTH = 12;

    public DslEditorView() {
        super(ID);
    }

    private SashForm mainSash;
    private ProjectionViewer dslEditorViewer;
    private IDocument dslEditorDocument;
    private StyledText previewOutput;

    private IFn dslFn;
    private byte[] baData;

    @Override
    public void createPartControl(Composite parent) {
        this.mainSash = new SashForm(parent, SWT.HORIZONTAL);

        CompositeRuler dslEditorRuler = new CompositeRuler(RULER_WIDTH);
        dslEditorRuler.addDecorator(0, new LineNumberRulerColumn());

        this.dslEditorViewer = new ProjectionViewer(this.mainSash, dslEditorRuler,
                new OverviewRuler(null, RULER_WIDTH, null), true, SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
        this.dslEditorViewer.getControl().setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        ProjectionAnnotationModel pam = new ProjectionAnnotationModel();
        dslEditorRuler.setModel(pam);
        
        this.dslEditorDocument = new Document();
        this.dslEditorDocument.set(Helper.getDslExpression());

        pam.connect(this.dslEditorDocument);
        pam.addAnnotation(new ProjectionAnnotation(), new Position(0, 23));
        pam.addAnnotation(new ProjectionAnnotation(), new Position(20, 100));
        pam.addAnnotation(new ProjectionAnnotation(), new Position(120, 400));
        
        ProjectionSupport dslEditorProjectionSupport = new ProjectionSupport(this.dslEditorViewer,
                new DefaultMarkerAnnotationAccess(), EditorsPlugin.getDefault().getSharedTextColors());

        dslEditorProjectionSupport.install();
        this.dslEditorViewer.doOperation(ProjectionViewer.TOGGLE);        

        this.dslEditorViewer.addTextListener(new ITextListener() {

            @Override
            public void textChanged(TextEvent event) {
                String dslExpression = dslEditorDocument.get();

                if (dslExpression == null || dslExpression.isEmpty()) {
                    return;
                }

                try {
                    dslFn = DslHelper.generateProcessingFn(dslExpression);
                    System.out.println("Successfully generated processing function.");
                    updatePreview();
                } catch (Exception e) {
                    if (previewOutput != null) {
                        previewOutput.setText("Failed to generated processing funtion:\n" + e.getMessage());
                    }
                    System.out.println("Caught exception while generating processing function from DSL.");
                    e.printStackTrace();
                }
            }
        });
        

        this.dslEditorViewer.showAnnotations(true);
        this.dslEditorViewer.setDocument(this.dslEditorDocument, pam);
        

        this.previewOutput = new StyledText(this.mainSash, SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
    }

    @Override
    public void setFocus() {
        // TODO Auto-generated method stub

    }

    @TmfSignalHandler
    public void eventSelected(final TmfEventSelectedSignal signal) {
        System.out.println("Event selected...");

        ITmfEvent event = signal.getEvent();
        if (!(event instanceof PcapDslEvent)) {
            return;
        }

        PcapDslEvent pcapDslEvent = (PcapDslEvent) event;

        Map<String, Object> packetMap = pcapDslEvent.getPacketMap();
        if (packetMap == null || !(packetMap.get(PcapDslFile.PCAP_RAW_DATA) instanceof byte[])) {
            return;
        }

        this.baData = (byte[]) packetMap.get(PcapDslFile.PCAP_RAW_DATA);
        updatePreview();
    }

    private void updatePreview() {
        if (this.baData == null) {
            if (this.previewOutput != null) {
                this.previewOutput.setText("Preview data is invalid.");
            }
            return;
        }

        if (this.dslFn == null) {
            if (this.previewOutput != null) {
                this.previewOutput.setText("DSL function is invalid.");
            }
            return;
        }

        Object dslOut = dslFn.invoke(this.baData);
        // System.out.println("DSL Output: " + String.valueOf(dslOut));

        if (dslOut instanceof Map) {
            Map<String, Object> packetDataMap = (Map<String, Object>) dslOut;
            String outString = DslHelper.prettyPrint(packetDataMap);
            this.previewOutput.setText(outString.replaceAll(", ", "\n"));
        }
    }
}
