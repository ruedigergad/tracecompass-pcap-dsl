package pcap.dsl.core.ui.preferences;

import org.eclipse.jface.preference.FieldEditorPreferencePage;
import org.eclipse.jface.preference.FileFieldEditor;
import org.eclipse.jface.preference.StringFieldEditor;
import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

import pcap.dsl.core.Activator;
import pcap.dsl.core.config.Constants;

public class DslPreferencePage extends FieldEditorPreferencePage implements IWorkbenchPreferencePage {

    public DslPreferencePage() {
        // TODO Auto-generated constructor stub
    }

    public DslPreferencePage(int style) {
        super(style);
        // TODO Auto-generated constructor stub
    }

    public DslPreferencePage(String title, int style) {
        super(title, style);
        // TODO Auto-generated constructor stub
    }

    public DslPreferencePage(String title, ImageDescriptor image, int style) {
        super(title, image, style);
        // TODO Auto-generated constructor stub
    }

    @Override
    public void init(IWorkbench workbench) {
        setPreferenceStore(Activator.getDefault().getPreferenceStore());
    }

    @Override
    protected void createFieldEditors() {
        StringFieldEditor dslExpressionFileEditor = new FileFieldEditor(Constants.DSL_FILE_CONFIG_KEY,
                Constants.DSL_FILE_CONFIG_LABEL, getFieldEditorParent());
        addField(dslExpressionFileEditor);
    }

    @Override
    public boolean isValid() {
        return true;
    }

}
