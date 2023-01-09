package ghidravsa;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;




@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Provide value set analysis functionality to Ghidra by leveraging angr.",
    description = "Provide value set analysis functionality to Ghidra by leveraging angr."
)

public class GhidraVSAPlugin extends ProgramPlugin {

    GhidraVSAProvider provider;
    Program program;
    GhidraVSAPopupMenu popup;

    public GhidraVSAPlugin(PluginTool tool) {
        super(tool, true, true);
        String pluginName = getName();
        provider = new GhidraVSAProvider(this, pluginName, this.getCurrentProgram());
        createActions();
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    protected void programActivated(Program p) {
        program = p;
        provider.setProgram(p);
        popup.setProgram(p);
    }

    private void createActions() {
        popup = new GhidraVSAPopupMenu(this, program);
    }
}
