package pcap.dsl.core.ui.preferences;

/*
 * Copyright 2017, Ruediger Gad
 * 
 * This software is released under the terms of the Eclipse Public License 
 * (EPL) 1.0. You can find a copy of the EPL at: 
 * http://opensource.org/licenses/eclipse-1.0.php
 * 
 */

import org.eclipse.jface.preference.FieldEditorPreferencePage;
import org.eclipse.jface.preference.FileFieldEditor;
import org.eclipse.jface.preference.StringFieldEditor;
import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

import pcap.dsl.core.Activator;
import pcap.dsl.core.config.Constants;

/**
 * Preference page for settings related to the DSL-based packet capture
 * processing.
 * 
 * @author &lt;r.c.g@gmx.de&gt;
 *
 */
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
