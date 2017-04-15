package pcap.dsl.ui.view;

import java.util.Map;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.signal.TmfEventSelectedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfSignalHandler;
import org.eclipse.tracecompass.tmf.ui.views.TmfView;

import clojure.lang.IFn;
import dsbdp.DslHelper;
import pcap.dsl.core.event.PcapDslEvent;
import pcap.dsl.core.trace.PcapDslFile;
import pcap.dsl.core.util.Helper;

public class DslEditorView extends TmfView {

    public static final String ID = "pcap.dsl.core.DslEditorView";

    public DslEditorView() {
        super(ID);
    }

    private SashForm mainSash;
    private StyledText dslEditorInput;
    private StyledText previewOutput;
    private IFn dslFn;

    @Override
    public void createPartControl(Composite parent) {
        this.mainSash = new SashForm(parent, SWT.HORIZONTAL);

        this.dslEditorInput = new StyledText(this.mainSash, SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
        this.dslEditorInput.addModifyListener(new ModifyListener() {

            @Override
            public void modifyText(ModifyEvent event) {
                String dslExpression = dslEditorInput.getText();

                if (dslExpression == null || dslExpression.isEmpty()) {
                    return;
                }

                try {
                    dslFn = DslHelper.generateProcessingFn(dslExpression);
                    System.out.println("Successfully generated processing function.");
                } catch (Exception e) {
                    System.out.println("Caught exception while generating processing function from DSL.");
                    e.printStackTrace();
                }
            }
        });
        this.dslEditorInput.setText(Helper.getDslExpression());

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

        byte[] baData = (byte[]) packetMap.get(PcapDslFile.PCAP_RAW_DATA);
        updatePreview(baData);
    }
    
    private void updatePreview(byte[] baData) {
        if (baData == null || dslFn == null) {
            return;
        }
        
        Object dslOut = dslFn.invoke(baData);
        //System.out.println("DSL Output: " + String.valueOf(dslOut));

        if (dslOut instanceof Map) {
            Map<String, Object> packetDataMap = (Map<String, Object>) dslOut;
            this.previewOutput.setText(String.valueOf(packetDataMap));
        }
    }
}
