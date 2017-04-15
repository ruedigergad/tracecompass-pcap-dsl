package pcap.dsl.ui.view;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.ui.part.ViewPart;

import pcap.dsl.core.util.Helper;

public class DslEditorView extends ViewPart {

    private SashForm mainSash;
    private StyledText dslEditorInput;
    private StyledText previewOutput;
    
    @Override
    public void createPartControl(Composite parent) {
        this.mainSash = new SashForm(parent, SWT.HORIZONTAL);
        
        this.dslEditorInput = new StyledText(this.mainSash, SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
        this.dslEditorInput.setText(Helper.getDslExpression());
        
        this.previewOutput = new StyledText(this.mainSash, SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
    }

    @Override
    public void setFocus() {
        // TODO Auto-generated method stub

    }

}
