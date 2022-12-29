package ghidravsa;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.FlowLayout;
import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import org.json.JSONArray;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class GhidraVSAProvider extends ComponentProvider {

    private JPanel panel;
    private String tmpDir;
    private Program program;

    public GhidraVSAProvider(GhidraVSAPlugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/Ico.png"));
        setProgram(program);
        buildPanel();
    }

    private void buildPanel() {
        panel = new JPanel();
        panel.setMinimumSize(new Dimension(210, 510));
        setVisible(true);

        ImageIcon Addicon = new ImageIcon(getClass().getResource("/images/add.png"));
        Font labelFont = new Font("SansSerif", Font.PLAIN, 12);

        tmpDir = System.getProperty("java.io.tmpdir");
        if (System.getProperty("os.name").contains("Windows") == false) {
        	tmpDir += "/";
        }

        Border blackline = BorderFactory.createLineBorder(Color.black);


        JPanel instrPanel = new JPanel();
        instrPanel.setForeground(new Color(46, 139, 87));
        instrPanel.setLayout(new FlowLayout(FlowLayout.LEADING));

        JLabel instrLabel = new JLabel("Instruction Address:");
        instrLabel.setFont(labelFont);
        IntegerTextField instrField = new IntegerTextField();
        instrField.setHexMode();

        instrPanel.add(instrLabel);
        instrPanel.add(instrField.getComponent());

        JPanel regPanel = new JPanel();
        TitledBorder regPanelBorder = BorderFactory.createTitledBorder("Find Register Value:");
        regPanelBorder.setTitleFont(labelFont);
        regPanel.setBorder(regPanelBorder);
        regPanel.setLayout(new BorderLayout());

        JPanel regInputsPanel = new JPanel();
        regInputsPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // regInputsPanel.setBorder(blackline);
        JLabel regPanelRegLabel = new JLabel("Register:");
        regPanelRegLabel.setFont(labelFont);
        JTextField regPanelRegInput = new JTextField("", 4);
        regInputsPanel.add(regPanelRegLabel);
        regInputsPanel.add(regPanelRegInput);

        JPanel regButtonPanel = new JPanel();
        regButtonPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // regButtonPanel.setBorder(blackline);
        JButton regButton = new JButton("Go!");
        regButtonPanel.add(regButton);

        regPanel.add(regInputsPanel, BorderLayout.PAGE_START);
        regPanel.add(regButtonPanel, BorderLayout.PAGE_END);


        JPanel memPanel = new JPanel();
        TitledBorder memPanelBorder = BorderFactory.createTitledBorder("Find Memory Value:");
        memPanelBorder.setTitleFont(labelFont);
        memPanel.setBorder(memPanelBorder);
        memPanel.setLayout(new BorderLayout());

        JPanel memInputsPanel = new JPanel();
        memInputsPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // memInputsPanel.setBorder(blackline);
        JLabel memPanelAddrLabel = new JLabel("Address:");
        memPanelAddrLabel.setFont(labelFont);
        IntegerTextField memPanelAddrInput = new IntegerTextField();
        memPanelAddrInput.setHexMode();
        JLabel memPanelTypeLabel = new JLabel("    Type to interpret:");
        memPanelTypeLabel.setFont(labelFont);
        JTextField memPanelTypeInput = new JTextField("", 6);
        memInputsPanel.add(memPanelAddrLabel);
        memInputsPanel.add(memPanelAddrInput.getComponent());
        memInputsPanel.add(memPanelTypeLabel);
        memInputsPanel.add(memPanelTypeInput);

        JPanel memButtonPanel = new JPanel();
        memButtonPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // memButtonPanel.setBorder(blackline);
        JButton memButton = new JButton("Go!");
        memButtonPanel.add(memButton);

        memPanel.add(memInputsPanel, BorderLayout.CENTER);
        memPanel.add(memButtonPanel, BorderLayout.PAGE_END);

        JPanel offsetPanel = new JPanel();
        TitledBorder offsetPanelBorder = BorderFactory.createTitledBorder("Find Register Offset Value:");
        offsetPanelBorder.setTitleFont(labelFont);
        offsetPanel.setBorder(offsetPanelBorder);
        offsetPanel.setLayout(new BorderLayout());

        JPanel offsetInputsPanel = new JPanel();
        offsetInputsPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // offsetInputsPanel.setBorder(blackline);
        JLabel offsetPanelRegLabel = new JLabel("Register:");
        offsetPanelRegLabel.setFont(labelFont);
        JLabel offsetPanelOffsetLabel = new JLabel("    Offset:");
        offsetPanelOffsetLabel.setFont(labelFont);
        JTextField offsetPanelRegInput = new JTextField("", 4);
        IntegerTextField offsetPanelOffsetInput = new IntegerTextField();
        offsetPanelOffsetInput.setHexMode();
        JLabel offsetPanelTypeLabel = new JLabel("    Type to interpret:");
        offsetPanelTypeLabel.setFont(labelFont);
        JTextField offsetPanelTypeInput = new JTextField("", 6);
        offsetInputsPanel.add(offsetPanelRegLabel);
        offsetInputsPanel.add(offsetPanelRegInput);
        offsetInputsPanel.add(offsetPanelOffsetLabel);
        offsetInputsPanel.add(offsetPanelOffsetInput.getComponent());
        offsetInputsPanel.add(offsetPanelTypeLabel);
        offsetInputsPanel.add(offsetPanelTypeInput);

        JPanel offsetButtonPanel = new JPanel();
        offsetButtonPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // offsetButtonPanel.setBorder(blackline);
        JButton offsetButton = new JButton("Go!");
        offsetButtonPanel.add(offsetButton);

        offsetPanel.add(offsetInputsPanel, BorderLayout.CENTER);
        offsetPanel.add(offsetButtonPanel, BorderLayout.PAGE_END);

        JPanel resultPanel = new JPanel();
        TitledBorder resultPanelBorder = BorderFactory.createTitledBorder("Result:");
        resultPanelBorder.setTitleFont(labelFont);
        resultPanel.setBorder(resultPanelBorder);
        resultPanel.setLayout(new BorderLayout());

        JTextArea resultArea = new JTextArea();
        // resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        JScrollPane resultScrollPane = new JScrollPane(resultArea);
        resultScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        resultScrollPane.setPreferredSize(new Dimension(100, 200));

        resultPanel.add(resultScrollPane);



        panel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;
        c.weightx = .5;
        c.weighty = .01;
        c.gridx = 0;
        c.gridy = 0;
        panel.add(instrPanel, c);
        c.gridy = 1;
        panel.add(regPanel, c);
        c.gridy = 2;
        panel.add(memPanel, c);
        c.gridy = 3;
        panel.add(offsetPanel, c);
        c.gridy = 4;
        c.weighty = .99;
        panel.add(resultPanel, c);


        
    }



    @Override
    public JComponent getComponent() {
        return panel;
    }


    public void setProgram(Program p) {
        program = p;
    }

}
