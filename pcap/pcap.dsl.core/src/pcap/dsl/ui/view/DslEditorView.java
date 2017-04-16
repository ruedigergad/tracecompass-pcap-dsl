package pcap.dsl.ui.view;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.jface.text.Document;
import org.eclipse.jface.text.DocumentEvent;
import org.eclipse.jface.text.IDocument;
import org.eclipse.jface.text.IDocumentListener;
import org.eclipse.jface.text.ITextListener;
import org.eclipse.jface.text.Position;
import org.eclipse.jface.text.TextEvent;
import org.eclipse.jface.text.source.CompositeRuler;
import org.eclipse.jface.text.source.IAnnotationAccess;
import org.eclipse.jface.text.source.LineNumberRulerColumn;
import org.eclipse.jface.text.source.projection.ProjectionAnnotation;
import org.eclipse.jface.text.source.projection.ProjectionAnnotationModel;
import org.eclipse.jface.text.source.projection.ProjectionSupport;
import org.eclipse.jface.text.source.projection.ProjectionViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
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
    private Pattern dslEditorFoldStartPattern = Pattern.compile("(?s)\\[\\s*\\[");
    private Pattern dslEditorFoldEndPattern = Pattern.compile("(?s)\\]\\s*\\]");
    private ProjectionAnnotation[] dslEditorOldAnnotations = new ProjectionAnnotation[] {};

    private ProjectionViewer outputViewer;
    private IDocument outputDocument;

    private IFn dslFn;
    private byte[] baData;

    @Override
    public void createPartControl(Composite parent) {
        this.mainSash = new SashForm(parent, SWT.HORIZONTAL);

        CompositeRuler dslEditorVerticalRuler = new CompositeRuler(RULER_WIDTH);
        dslEditorVerticalRuler.addDecorator(0, new LineNumberRulerColumn());

        this.dslEditorViewer = new ProjectionViewer(this.mainSash, dslEditorVerticalRuler, null, false,
                SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);

        this.dslEditorViewer.addTextListener(new ITextListener() {

            @Override
            public void textChanged(TextEvent event) {

            }
        });

        IAnnotationAccess editorMarkerAnnotationAccess = new DefaultMarkerAnnotationAccess();
        ProjectionSupport dslEditorProjectionSupport = new ProjectionSupport(this.dslEditorViewer,
                editorMarkerAnnotationAccess, EditorsPlugin.getDefault().getSharedTextColors());
        dslEditorProjectionSupport.install();

        this.dslEditorViewer.doOperation(ProjectionViewer.TOGGLE);

        this.dslEditorDocument = new Document();
        ProjectionAnnotationModel pam = new ProjectionAnnotationModel();

        this.dslEditorDocument.addDocumentListener(new IDocumentListener() {

            @Override
            public void documentChanged(DocumentEvent event) {
                String dslExpression = dslEditorDocument.get();

                if (dslExpression == null || dslExpression.isEmpty()) {
                    return;
                }

                updateDslEditorFolding();

                try {
                    dslFn = DslHelper.generateProcessingFn(dslExpression);
                    System.out.println("Successfully generated processing function.");
                    updatePreview();
                } catch (Exception e) {
                    if (outputDocument != null) {
                        outputDocument.set("Failed to generated processing funtion:\n" + e.getMessage());
                    }
                    System.out.println("Caught exception while generating processing function from DSL.");
                    e.printStackTrace();
                }
            }

            @Override
            public void documentAboutToBeChanged(DocumentEvent event) {
                // TODO Auto-generated method stub

            }
        });

        this.dslEditorViewer.enableProjection();
        this.dslEditorViewer.setDocument(this.dslEditorDocument, pam);
        this.dslEditorViewer.enableProjection();
        this.dslEditorViewer.setDocument(this.dslEditorDocument, pam);
        this.dslEditorDocument.set(Helper.getDslExpression());

        CompositeRuler outputVerticalRuler = new CompositeRuler(RULER_WIDTH);
        outputVerticalRuler.addDecorator(0, new LineNumberRulerColumn());

        this.outputViewer = new ProjectionViewer(this.mainSash, outputVerticalRuler, null, false,
                SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);

        IAnnotationAccess outputMarkerAnnotationAccess = new DefaultMarkerAnnotationAccess();
        ProjectionSupport outputProjectionSupport = new ProjectionSupport(this.outputViewer,
                outputMarkerAnnotationAccess, EditorsPlugin.getDefault().getSharedTextColors());
        outputProjectionSupport.install();

        this.outputViewer.doOperation(ProjectionViewer.TOGGLE);

        this.outputDocument = new Document();
        ProjectionAnnotationModel pam2 = new ProjectionAnnotationModel();

        this.outputViewer.enableProjection();
        this.outputViewer.setDocument(this.outputDocument, pam2);
        this.outputViewer.enableProjection();
        this.outputViewer.setDocument(this.outputDocument, pam2);
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
            if (this.outputDocument != null) {
                this.outputDocument.set("Preview data is invalid.");
            }
            return;
        }

        if (this.dslFn == null) {
            if (this.outputDocument != null) {
                this.outputDocument.set("DSL function is invalid.");
            }
            return;
        }

        Object dslOut = dslFn.invoke(this.baData);
        // System.out.println("DSL Output: " + String.valueOf(dslOut));

        if (dslOut instanceof Map) {
            Map<String, Object> packetDataMap = (Map<String, Object>) dslOut;
            String outString = DslHelper.prettyPrint(packetDataMap);
            this.outputDocument.set(outString.replaceAll(", ", "\n"));
        }
    }

    private void updateDslEditorFolding() {
        ProjectionAnnotationModel annotationModel = this.dslEditorViewer.getProjectionAnnotationModel();
        if (annotationModel == null) {
            return;
        }

        Matcher foldStartMatcher = this.dslEditorFoldStartPattern.matcher(this.dslEditorDocument.get());
        List<Position> foldStartPositions = new ArrayList<>();
        while (foldStartMatcher.find()) {
            foldStartPositions.add(new Position(foldStartMatcher.start()));
        }

        Matcher foldEndMatcher = this.dslEditorFoldEndPattern.matcher(this.dslEditorDocument.get());
        List<Integer> foldEndIndices = new ArrayList<>();
        while (foldEndMatcher.find()) {
            foldEndIndices.add(foldEndMatcher.end());
        }

        System.out.println("Fold Start: " + String.valueOf(foldStartPositions));
        System.out.println("Fold End: " + String.valueOf(foldEndIndices));

        // foldStartPositions.get(0)
        // .setLength(foldEndIndices.get(foldEndIndices.size() - 1) -
        // foldStartPositions.get(0).getOffset());

        Set<Integer> matchedStartIdx = new HashSet<>();
        matchedStartIdx.add(0);
        Set<Integer> matchedEndIdx = new HashSet<>();
        matchedEndIdx.add(foldEndIndices.size() - 1);

        int startIdx = 1;
        int maxStartIdx = startIdx;
        int endIdx = 0;
        int currentStartOffset = foldStartPositions.get(startIdx).getOffset();
        int currentEndOffset = foldEndIndices.get(endIdx);
        while (startIdx >= 1 && endIdx >= 0 && startIdx < foldStartPositions.size() + 1
                && endIdx < foldEndIndices.size() - 1) {
            System.out.println(currentStartOffset + " < " + currentEndOffset);

            if (currentStartOffset < currentEndOffset && maxStartIdx < foldStartPositions.size()) {
                do {
                    startIdx++;
                } while (matchedStartIdx.contains(startIdx));

                if (startIdx < foldStartPositions.size()) {
                    currentStartOffset = foldStartPositions.get(startIdx).getOffset();
                } else {
                    currentStartOffset = Integer.MAX_VALUE;
                }

                continue;
            } else if (maxStartIdx >= foldStartPositions.size()) {
                while (matchedStartIdx.contains(startIdx)) {
                    startIdx--;
                }
            }

            matchedStartIdx.add(startIdx);

            Position prevStartPosition = foldStartPositions.get(startIdx - 1);

            maxStartIdx = Math.max(maxStartIdx, startIdx);

            System.out.println(
                    prevStartPosition.getOffset() + " - " + (currentEndOffset - prevStartPosition.getOffset()));
            prevStartPosition.setLength(currentEndOffset - prevStartPosition.getOffset() + 1);

            endIdx++;
            if (foldEndIndices.size() < endIdx) {
                endIdx = -1;
                continue;
            }
            currentEndOffset = foldEndIndices.get(endIdx);

            while (matchedStartIdx.contains(startIdx - 1)) {
                startIdx--;
                currentStartOffset = foldStartPositions.get(startIdx).getOffset();
            }
        }

        System.out.println("FOOOOOOOOOOOOOOOOO" + String.valueOf(foldStartPositions));

        ProjectionAnnotation[] currentAnnotations = new ProjectionAnnotation[foldStartPositions.size()];
        Map<ProjectionAnnotation, Position> newAnnotations = new HashMap<>();
        for (int i = 0; i < foldStartPositions.size(); i++) {
            Position pos = foldStartPositions.get(i);
            currentAnnotations[i] = new ProjectionAnnotation();
            newAnnotations.put(currentAnnotations[i], pos);
        }
        annotationModel.modifyAnnotations(this.dslEditorOldAnnotations, newAnnotations, null);
        this.dslEditorOldAnnotations = currentAnnotations;
    }
}
