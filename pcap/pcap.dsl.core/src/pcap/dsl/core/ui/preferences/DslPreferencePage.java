package pcap.dsl.core.ui.preferences;

import org.eclipse.jface.preference.FieldEditorPreferencePage;
import org.eclipse.jface.preference.StringFieldEditor;
import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

public class DslPreferencePage extends FieldEditorPreferencePage implements IWorkbenchPreferencePage {

	public static final String DSL_EXPRESSION = "dsl_expression";
	public static final String DSL_EXPRESSION_LABEL = "DSL Expression";
	
	
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
		// TODO Auto-generated method stub

	}

	@Override
	protected void createFieldEditors() {
		StringFieldEditor dslExpressionEditor = new StringFieldEditor(DSL_EXPRESSION, DSL_EXPRESSION_LABEL, getFieldEditorParent());
        addField(dslExpressionEditor);
	}

}
