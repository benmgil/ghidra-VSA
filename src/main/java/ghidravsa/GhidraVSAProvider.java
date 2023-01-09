package ghidravsa;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.FlowLayout;
import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import org.json.JSONArray;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class GhidraVSAProvider extends ComponentProvider {
    static IntegerTextField instrInput;
    private JTextField regPanelRegInput;
    private JButton regButton;
    private IntegerTextField memPanelAddrInput;
    private JTextField memPanelTypeInput;
    private JButton memButton;
    private JTextField offsetPanelRegInput;
    private IntegerTextField offsetPanelOffsetInput;
    private JTextField offsetPanelTypeInput;
    private JButton offsetButton;
    static JTextArea resultArea;

    private JPanel panel;
    private String tmpDir;
    private Program program;
    private boolean isTerminated;
    private boolean isRunning;
    private String solution;

    public GhidraVSAProvider(GhidraVSAPlugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/Ico.png"));
        setProgram(program);
        isTerminated = false;
        isRunning = false;
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
        instrInput = new IntegerTextField(16);
        instrInput.setHexMode();
        instrInput.getComponent().addKeyListener(new KeyAdapter(){
            public void keyReleased(KeyEvent e){
                if (GhidraVSAPopupMenu.instrAddr != null){
                    GhidraVSAPopupMenu.unsetColor(GhidraVSAPopupMenu.instrAddr);
                }
                String input = instrInput.getText();
                if (input.isEmpty() || input.equals("0") || input.equals("0x"))
                    return;

                Address generic = program.getListing().getInstructions(true).next().getAddress();

                long convertedInput = Long.decode(instrInput.getText());
                Address newAddress = generic.getNewAddress(convertedInput);
                GhidraVSAPopupMenu.instrAddr = newAddress;
                GhidraVSAPopupMenu.setColor(newAddress, Color.MAGENTA);
            }
        });

        instrPanel.add(instrLabel);
        instrPanel.add(instrInput.getComponent());

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
        regPanelRegInput = new JTextField("", 4);
        regInputsPanel.add(regPanelRegLabel);
        regInputsPanel.add(regPanelRegInput);

        JPanel regButtonPanel = new JPanel();
        regButtonPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // regButtonPanel.setBorder(blackline);
        regButton = new JButton("Go!");
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
        memPanelAddrInput = new IntegerTextField(16);
        memPanelAddrInput.setHexMode();
        JLabel memPanelTypeLabel = new JLabel("    Type to interpret:");
        memPanelTypeLabel.setFont(labelFont);
        memPanelTypeInput = new JTextField("", 6);
        memInputsPanel.add(memPanelAddrLabel);
        memInputsPanel.add(memPanelAddrInput.getComponent());
        memInputsPanel.add(memPanelTypeLabel);
        memInputsPanel.add(memPanelTypeInput);

        JPanel memButtonPanel = new JPanel();
        memButtonPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // memButtonPanel.setBorder(blackline);
        memButton = new JButton("Go!");
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
        offsetPanelRegInput = new JTextField("", 4);
        JLabel offsetPanelOffsetLabel = new JLabel("    Offset:");
        offsetPanelOffsetLabel.setFont(labelFont);
        offsetPanelOffsetInput = new IntegerTextField(6);
        offsetPanelOffsetInput.setHexMode();
        JLabel offsetPanelTypeLabel = new JLabel("    Type to interpret:");
        offsetPanelTypeLabel.setFont(labelFont);
        offsetPanelTypeInput = new JTextField("", 6);
        offsetInputsPanel.add(offsetPanelRegLabel);
        offsetInputsPanel.add(offsetPanelRegInput);
        offsetInputsPanel.add(offsetPanelOffsetLabel);
        offsetInputsPanel.add(offsetPanelOffsetInput.getComponent());
        offsetInputsPanel.add(offsetPanelTypeLabel);
        offsetInputsPanel.add(offsetPanelTypeInput);

        JPanel offsetButtonPanel = new JPanel();
        offsetButtonPanel.setLayout(new FlowLayout(FlowLayout.LEADING));
        // offsetButtonPanel.setBorder(blackline);
        offsetButton = new JButton("Go!");
        offsetButtonPanel.add(offsetButton);

        offsetPanel.add(offsetInputsPanel, BorderLayout.CENTER);
        offsetPanel.add(offsetButtonPanel, BorderLayout.PAGE_END);

        JPanel resultPanel = new JPanel();
        TitledBorder resultPanelBorder = BorderFactory.createTitledBorder("Result:");
        resultPanelBorder.setTitleFont(labelFont);
        resultPanel.setBorder(resultPanelBorder);
        resultPanel.setLayout(new BorderLayout());

        resultArea = new JTextArea();
        resultArea.setEditable(false);
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


        regButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (!isRunning){
                    JSONObject vsaOptions = new JSONObject();
                    vsaOptions.put("target", "register");

                    JSONObject args = new JSONObject();
                    String instruction = instrInput.getText();
                    args.put("instruction", instruction);
                    String register = regPanelRegInput.getText();
                    args.put("register", register);
                    vsaOptions.put("args", args);

                    isRunning = true;
                    regButton.setText("Stop");
                    memButton.setEnabled(false);
                    offsetButton.setEnabled(false);

                    setupOptions(vsaOptions);
                }
                else{
                    isTerminated = true;
                }
            }
        });

        memButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (!isRunning){
                    JSONObject vsaOptions = new JSONObject();
                    vsaOptions.put("target", "memory");

                    JSONObject args = new JSONObject();
                    String instruction = instrInput.getText();
                    args.put("instruction", instruction);
                    String addr = memPanelAddrInput.getText();
                    args.put("addr", addr);
                    String type = memPanelTypeInput.getText();
                    args.put("type", type);
                    vsaOptions.put("args", args);

                    isRunning = true;
                    memButton.setText("Stop");
                    regButton.setEnabled(false);
                    offsetButton.setEnabled(false);

                    setupOptions(vsaOptions);
                }
                else{
                    isTerminated = true;
                }
            }
        });

        offsetButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if (!isRunning){
                    JSONObject vsaOptions = new JSONObject();
                    vsaOptions.put("target", "offset");

                    JSONObject args = new JSONObject();
                    String instruction = instrInput.getText();
                    args.put("instruction", instruction);
                    String register = offsetPanelRegInput.getText();
                    args.put("register", register);
                    String offset = offsetPanelOffsetInput.getText();
                    args.put("offset", offset);
                    String type = offsetPanelTypeInput.getText();
                    args.put("type", type);
                    vsaOptions.put("args", args);

                    isRunning = true;
                    offsetButton.setText("Stop");
                    regButton.setEnabled(false);
                    memButton.setEnabled(false);

                    setupOptions(vsaOptions);
                }
                else{
                    isTerminated = true;
                }
            }
        });
    }


    private void setupOptions(JSONObject vsaOptions){
        resultArea.setText("Starting VSA...");

        String binaryPath = program.getExecutablePath();
        if (System.getProperty("os.name").contains("windows")){
            binaryPath = binaryPath.replaceFirst("/", "");
            binaryPath = binaryPath.replace("/", "\\");
        }
        vsaOptions.put("binary_file", binaryPath);

        // if (program.getExecutableFormat().contains("Raw Binary")){
            JSONObject binaryDetails = new JSONObject();
            String arch = program.getLanguage().toString().substring(0, program.getLanguage().toString().indexOf("/"));
            binaryDetails.put("arch", arch);
            binaryDetails.put("base", "0x" + Long.toHexString(program.getMinAddress().getOffset()));
            vsaOptions.put("binary_details", binaryDetails);
        // }

        File optionsFile = new File(tmpDir + "vsa_options.json");
        if (optionsFile.exists()){
            optionsFile.delete();
        }
        try{
            FileWriter fw = new FileWriter(tmpDir + "vsa_options.json");
            fw.write(vsaOptions.toString());
            fw.flush();
            fw.close();
        }
        catch (Exception ex) {
            resultArea.setText("");
            resultArea.append("Error writing VSA options to temp file\n");
            resultArea.append(ex.toString());

            reset();
            return;
        }

        setupPython(optionsFile);
    }

    private void setupPython(File optionsFile){
        if (isTerminated){
            reset();
            return;
        }
        solution = "";

        SwingWorker sw = new SwingWorker() {

            @Override
            protected String doInBackground() throws Exception{
                String basePath = null;

                try{
                    basePath = new File(GhidraVSAProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
                }
                catch (URISyntaxException ex){
                    resultArea.setText("");
                    resultArea.append("Error getting path to VSA script\n");
                    resultArea.append(ex.toString());

                    return null;
                }
                basePath = basePath.substring(0, basePath.indexOf("lib"));
                String scriptPath = basePath + "vsa_script" + File.separator + "vsa.py";
                File scriptFile = new File(scriptPath);

                if (runVSA("python3", scriptFile.getAbsolutePath(), optionsFile.getAbsolutePath()) == 0){
                    ProcessBuilder pb = new ProcessBuilder("python", "--version");
                    try{
                        Process p = pb.start();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        String line = "";
                        while ((line = reader.readLine()) != null) {
                        	if (compareVersion(line.substring(7), "3.4") == -1 && compareVersion(line.substring(7), "3.0") == 1) {
                                if (!isTerminated){
                            		runVSA("python", scriptFile.getAbsolutePath(), optionsFile.getAbsolutePath());
                                }
                        	}
                            else{
                                resultArea.setText("");
                                resultArea.append("Error: Please use Python 3.0 - 3.4 or configure python3 command");
                                return null;
                            }
                        }
                        p.waitFor();
                        reader.close();
                    } catch (Exception ex) {
                        resultArea.setText("");
                        resultArea.append("Error checking Python version\n");
                        resultArea.append(ex.toString());

                        return null;
                    }
                }
                // optionsFile.delete();
                return null;
            }

            @Override
            protected void done(){
                if (isTerminated){
                    resultArea.setText("VSA process was terminated.");
                }
                else if(!solution.isEmpty()){
                    resultArea.setText(solution.trim());
                }
                solution = "";
                reset();

            }
        };
        sw.execute();
    }


    private int runVSA(String pythonVersion, String scriptPath, String optionsPath){
        if (isTerminated){
            return -1;
        }
        resultArea.setText("Running VSA...");
        solution += pythonVersion;
        solution += " ";
        solution += scriptPath;
        solution += " ";
        solution += optionsPath;
        solution += "\n";
        ProcessBuilder pb = new ProcessBuilder(pythonVersion, scriptPath, optionsPath);
        pb.redirectErrorStream(true);
        try{
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";
            while ((line = reader.readLine()) != null && !isTerminated){
                solution += line;
                solution += "\n";
            }
            if (isTerminated){
                p.destroy();
                reader.close();
                return -1;
            }
            p.waitFor();
            reader.close();
            if (solution.isEmpty()){
                solution = "VSA finished. No solution found";
            }
            return 1;
        }
        catch (Exception ex){
            if (pythonVersion.equals("python3")){
                return 0;
            }
            solution = "Error running VSA script\n";
            solution += ex.toString();
            resultArea.setText("");
            resultArea.append("Error running VSA script\n");
            resultArea.append(ex.toString());

            return 0;
        }
    }

    private void reset(){
        isTerminated = false;
        isRunning = false;

        regButton.setText("Go!");
        regButton.setEnabled(true);
        memButton.setText("Go!");
        memButton.setEnabled(true);
        offsetButton.setText("Go!");
        offsetButton.setEnabled(true);
    }

    private int compareVersion(String v1, String v2){
        String[] split1 = v1.split("\\.");
        String[] split2 = v2.split("\\.");

        int max = split2.length >= split1.length ? split2.length : split1.length;
        for (int i = 0; i < max; i++){
            if (i < split1.length && i < split2.length){
                if (Integer.parseInt(split1[i]) < Integer.parseInt(split2[i])){
                    return -1;
                }
                else if (Integer.parseInt(split1[i]) > Integer.parseInt(split2[i])){
                    return 1;
                }
            }
            else if (i < split1.length){
                if (Integer.parseInt(split1[i]) != 0){
                    return 1;
                }
            }
            else if (i < split2.length){
                if (Integer.parseInt(split2[i]) != 0){
                    return -1;
                }
            }
        }
        return 0;
    }


    @Override
    public JComponent getComponent() {
        return panel;
    }


    public void setProgram(Program p) {
        program = p;
    }

}
