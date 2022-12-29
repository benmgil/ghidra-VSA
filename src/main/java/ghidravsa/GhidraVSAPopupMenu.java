package ghidravsa;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import docking.action.MenuData;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class GhidraVSAPopupMenu extends ListingContextAction {
    public final String menuName = "GhidraVSAPlugin";
    public final String groupName = "SymEx";
    static Address instrAddr;
    public static PluginTool tool;
    public static Program program;

    public GhidraVSAPopupMenu(GhidraVSAPlugin plugin, Program program) {
        super("GhidraVSAPlugin", plugin.getName());
        setProgram(program);
        tool = plugin.getTool();
        setupActions();
    }

    public void setProgram(Program p) {
        program = p;
    }

    public void setupActions() {

        tool.setMenuGroup(new String[] {
            menuName
        }, groupName);

        ListingContextAction setInstrAddr = new ListingContextAction("Set VSA Address", getName()){

            @Override
            protected void actionPerformed(ListingActionContext context){
                if (instrAddr != null) {
                    unsetColor(instrAddr);
                }
                Address address = context.getLocation().getAddress();
                instrAddr = address;
                setColor(address, Color.MAGENTA);
                // GhidraVSAProvider.instrAddrField.setText("0x" + address.toString());
            }
        };

        setInstrAddr.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Set Instruction Address"
        }, null, groupName));

        tool.addAction(setInstrAddr);

        ListingContextAction unsetInstrAddr = new ListingContextAction("Unset VSA Address", getName()){

            @Override
            protected void actionPerformed(ListingActionContext context){
                Address address = context.getLocation().getAddress();
                unsetColor(address);
                instrAddr = null;
                // GhidraVSAProvider.instrAddrField.setText("");
            }
        };

        unsetInstrAddr.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Unset Instruction Address"
        }, null, groupName));

        tool.addAction(unsetInstrAddr);







        /*

        ListingContextAction ApplyPatchedBytes = new ListingContextAction("Apply Patched Bytes", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

            	Address MinAddress = context.getSelection().getMinAddress();
                AddressIterator addressRange = context.getSelection().getAddresses(true);
                StringBuilder HexStringBuilder = new StringBuilder();
                for (Address address: addressRange) {
                	byte Byte = 0;
					try {
						Byte = context.getProgram().getMemory().getByte(address);
					} catch (MemoryAccessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
                	HexStringBuilder.append(String.format("%02X", Byte));
                }
                String HexValueString = HexStringBuilder.toString();
                BigInteger HexValue = new BigInteger(HexValueString, 16);

                if (GhidraVSAProvider.TFstore_addr.getText().isEmpty() == false) {

                	IntegerTextField TFaddr = new IntegerTextField();
                	TFaddr.setHexMode();
                	TFaddr.setValue(MinAddress.getOffset());
                    GridBagConstraints gbc_TFaddr = new GridBagConstraints();
                    gbc_TFaddr.fill = GridBagConstraints.HORIZONTAL;
                    gbc_TFaddr.anchor = GridBagConstraints.NORTH;
                    gbc_TFaddr.gridx = 1;
                    gbc_TFaddr.insets = new Insets(0, 0, 0, 5);
                    gbc_TFaddr.gridy = GhidraVSAProvider.GuiStoreCounter;
                    gbc_TFaddr.weightx = 1;
                    gbc_TFaddr.weighty = 0.1;
                    GhidraVSAProvider.WMPanel.add(TFaddr.getComponent(), gbc_TFaddr);
                    GhidraVSAProvider.TFStoreAddrs.add(TFaddr);

                    IntegerTextField TFval = new IntegerTextField();
                    TFval.setHexMode();
                    TFval.setValue(HexValue);
                    GridBagConstraints gbc_TFval = new GridBagConstraints();
                    gbc_TFval.fill = GridBagConstraints.HORIZONTAL;
                    gbc_TFval.anchor = GridBagConstraints.NORTH;
                    gbc_TFval.insets = new Insets(0, 0, 0, 5);
                    gbc_TFval.gridx = 3;
                    gbc_TFval.gridy = GhidraVSAProvider.GuiStoreCounter;
                    gbc_TFval.weightx = 1;
                    gbc_TFval.weighty = 0.1;
                    GhidraVSAProvider.WMPanel.add(TFval.getComponent(), gbc_TFval);
                    GhidraVSAProvider.TFStoreVals.add(TFval);

                    JButton btnDel = new JButton("");
                    btnDel.setBorder(null);
                    btnDel.setContentAreaFilled(false);
                    btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
                    GridBagConstraints gbc_btnDel = new GridBagConstraints();
                    gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                    gbc_btnDel.anchor = GridBagConstraints.NORTH;
                    gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                    gbc_btnDel.gridx = 0;
                    gbc_btnDel.gridy = GhidraVSAProvider.GuiStoreCounter++;
                    gbc_btnDel.weighty = 0.1;
                    GhidraVSAProvider.WMPanel.add(btnDel, gbc_btnDel);
                    GhidraVSAProvider.delStore.add(btnDel);
                    btnDel.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                        	GhidraVSAProvider.GuiStoreCounter--;
                        	GhidraVSAProvider.WMPanel.remove(TFaddr.getComponent());
                        	GhidraVSAProvider.WMPanel.remove(TFval.getComponent());
                        	GhidraVSAProvider.WMPanel.remove(btnDel);
                        	GhidraVSAProvider.delStore.remove(btnDel);
                        	GhidraVSAProvider.TFStoreAddrs.remove(TFaddr);
                        	GhidraVSAProvider.TFStoreVals.remove(TFval);
                        	GhidraVSAProvider.WMPanel.repaint();
                        	GhidraVSAProvider.WMPanel.revalidate();
                        }

                    });
                    GhidraVSAProvider.WMPanel.repaint();
                    GhidraVSAProvider.WMPanel.revalidate();
                }
                else {
                	GhidraVSAProvider.TFstore_addr.setValue(MinAddress.getOffset());
                	GhidraVSAProvider.TFstore_val.setValue(HexValue);
                }

            }
        };
        ApplyPatchedBytes.setPopupMenuData(new MenuData(new String[] {
                MenuName,
                "Apply Patched Bytes"}, null, Group_Name));
        tool.addAction(ApplyPatchedBytes);

        */

    }

    public static void unsetColor(Address address) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("UnSetColor");
        service.clearBackgroundColor(address, address);
        program.endTransaction(TransactionID, true);

    }

    public static void setColor(Address address, Color color) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);

    }

}
