import sys
import angr
import claripy
import json
import time
import logging
import pickle
import os.path

print(angr.__file__)

EXPLORE_OPT = {}  # Explore options
REGISTERS = []  # Main registers of your binary
SYMVECTORS = []

def pickle_graph(graph, bin_name, graph_type):
    filename = bin_name + "_" + graph_type +".pickle"
    try:
        with open(filename, 'wb') as file:
            pickle.dump(graph, file, -1)
    except Exception as e:
        print(e)
        print(f"ERROR: COULD NOT PICKLE {graph_type.upper()} PICKLE")

def unpickle_graph(bin_name, graph_type):
    filename = bin_name + "_" + graph_type + ".pickle"
    if not os.path.exists(filename):
        return None

    try:
        with open(filename, 'rb') as file:
            graph = pickle.load(file)
            return graph
    except:
        print(f"ERROR: COULD NOT LOAD {graph_type.upper()} PICKLE")
        return None

def pickle_vfg(vfg, bin_name):
    pickle_graph(vfg, bin_name, "vfg")

def unpickle_vfg(bin_name):
    return unpickle_graph(bin_name, "vfg")

def pickle_cfg(cfg, bin_name):
    pickle_graph(cfg, bin_name, "cfg")

def unpickle_cfg(bin_name):
    return unpickle_graph(bin_name, "cfg")

def get_sorted_cfg(cfg):
    def cfg_sort(tup):
        return tup[0]
    sorted_cfg = []
    for addr, func in cfg.kb.functions.items():
        sorted_cfg.append((addr,func))
    sorted_cfg.sort(key=cfg_sort)
    return sorted_cfg

def print_cfg(cfg):
    sorted_cfg = get_sorted_cfg(cfg)
    print("CFG: ")
    print(len(sorted_cfg), " ITEMS")
    for (addr, func) in sorted_cfg:
        print("ADDR: ", hex(addr))
        print("FUNC: ", func)
        print(" ")


def instr_in_cfg(target_instr, cfg):
    sorted_cfg = get_sorted_cfg(cfg)

    same_block_count = 1
    targets = None
    curr_addr = None
    for i, (addr, func) in enumerate(sorted_cfg):
        prev_addr = curr_addr
        curr_addr = addr
        if curr_addr > target_instr:
            if i == 0:
                return False
            targets = sorted_cfg[i-same_block_count: i]
            break

        if prev_addr == curr_addr:
            same_block_count += 1
        else:
            same_block_count = 1

    if targets is not None:
        for (target_addr, target_func) in targets:
            for block in target_func.blocks:
                if block.addr <= target_instr and block.addr + block.size > target_instr:
                    return True
    return False



def get_sorted_vfg(vfg):
    def vfg_sort(tup):
        return tup[1].state.addr
    sorted_vfg = []
    for key, node in vfg._nodes.items():
        sorted_vfg.append((key,node))
    sorted_vfg.sort(key=vfg_sort)
    return sorted_vfg

def print_vfg(vfg):
    sorted_vfg = get_sorted_vfg(vfg)
    print("VFG: ")
    print(len(sorted_vfg), " ITEMS")
    for (key, node) in sorted_vfg:
        print(key)
        print(node)
        print(" ")

def get_val_at_instr(cfg, vfg, target_instr, target_str, val_getter):
    if not instr_in_cfg(target_instr, cfg):
        print("CANNOT DO VSA. TARGET INSTRUCTION NOT IN CFG")
        return
    sorted_vfg = get_sorted_vfg(vfg)

    targets = None
    curr_addr = None
    same_block_count = 1
    for i, (key, vfg_node) in enumerate(sorted_vfg):
        prev_addr = curr_addr
        curr_addr = vfg_node.state.addr
        # print(hex(curr_addr))

        if curr_addr > target_instr:
            if i == 0:
                print("ERROR: Target instruction is outside VFG analysis")
                return False

            targets = sorted_vfg[i-same_block_count: i]
            break

        if prev_addr == curr_addr:
            same_block_count += 1
        else:
            same_block_count = 1

    if targets is not None:
        for (target_block_id, target_node) in targets:
            node_addr = target_node.state.addr

            print("TARGET NODE:")
            print("\t ADDR:", hex(node_addr))
            print("\tBLOCK ID:", target_block_id)
            print("\tVFG NODE:", target_node)
            print("\tNUM FINAL STATES:", len(target_node.final_states))
            print("\tVALUES OF", target_str.upper(), "AT FINAL STATES: ")
            for i, state in enumerate(target_node.final_states):
                print("\tSTATE", i, ":")
                try:
                    val = val_getter(state)
                    print("\t\tVAL:", val)
                    print("\t\tCONCRETIZED:", hex(state.solver.eval(val)))
                    # print("\t\tOP:", val.op)
                    # print("\t\tAST ARGS:")
                    # for x in val.args:
                    #     print("\t\t\t", x)
                    # print("\t\tSIZES:", [x.size() for x in val.args])
                except Exception as e:
                    print("\t\tEXCEPTION: ", e)
            print("\tPREDECESSORS:")
            for pred in vfg.graph.predecessors(target_node):
                print ("\t\t", pred)
        print(" ")
    else:
        print("ERROR: Target instruction not found in VFG")

def get_reg_at_instr(cfg, vfg, target_instr, target_reg):
    def reg_getter(state):
        return state.regs.get("_"+target_reg)
    target_str = target_reg.upper()
    get_val_at_instr(cfg, vfg, target_instr, target_str, reg_getter)

def get_mem_at_instr(cfg, vfg, target_instr, target_mem, interp="int"):
    def mem_getter(state):
        return getattr(state.mem[target_mem], interp).resolved
    target_str = "[" + hex(target_mem).upper() + "]"
    get_val_at_instr(cfg, vfg, target_instr, target_str, mem_getter)

def get_reg_offset_at_instr(cfg, vfg, target_instr, target_reg, offset, interp="int"):
    def offset_getter(state):
        reg_val = state.regs.get("_"+target_reg)
        return getattr(state.mem[reg_val + offset], interp).resolved
    target_str = "[" + target_reg.upper() + " + " + hex(offset) + "]"
    get_val_at_instr(cfg, vfg, target_instr, target_str, offset_getter)



    #YOU WANT TO CHANGE REG OFFSET TO USE MEM
    #BUT FIRST YOU WANT TO TEST IT HOW IT IS TO SEE IF BOTH WAYS WORK
    #SO YOU LOOKED AT INSTR 11FF BUT WHY DOES THE NEXT BLOCK USE VAR_C


def figure_out_types():
    print("() len: ")
    print(len(vfg.graph.nodes().items()))
    print("_ len: ")
    print(len(vfg._nodes.items()))
    print(" ")

    print("() type:")
    print(type(vfg.graph.nodes()))
    print("_ type:")
    print(type(vfg._nodes))
    print(" ")

    list1 = list(vfg.graph.nodes().items())
    list2 = list(vfg._nodes.items())

    print("() items type:")
    print(type(list1[0]), type(list1[0][0]), type(list1[0][1]))
    print("_ items type:")
    print(type(list2[0]), type(list2[0][0]), type(list2[0][1]))
    print(" ")

    print("():")
    print(list1[0])
    print("_:")
    print(list2[0])

def hook_function(state):
    for object in EXPLORE_OPT["Hooks"]:
        for frame in object.items():
            if frame[0] == str(hex(state.solver.eval(state.regs.ip))):
                for option, data in frame[1].items():
                    if "sv" in data:
                        symbvector_length = int(data[2:], 0)
                        symbvector = claripy.BVS('symvector', symbvector_length * 8)
                        SYMVECTORS.append(symbvector)
                        data = symbvector
                    else:
                        data = int(str(data), 0)
                    for REG in REGISTERS:
                        if REG == option:
                            setattr(state.regs, option, data)
                            break

def main(file):
    t_0 = time.process_time()
    logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel('ERROR')

    with open(file, encoding='utf-8') as json_file:
        global EXPLORE_OPT
        EXPLORE_OPT = json.load(json_file)

    # Options parser
    # JSON can't handle with hex values, so we need to do it manually
    if "blank_state" in EXPLORE_OPT:
        blank_state = int(EXPLORE_OPT["blank_state"], 16)

    find = int(EXPLORE_OPT["find"], 16)

    if "avoid" in EXPLORE_OPT:
        avoid = [int(x, 16) for x in EXPLORE_OPT["avoid"].split(',')]

    # User can input hex or decimal value (argv length / symbolic memory length)
    argv = [EXPLORE_OPT["binary_file"]]
    if "Arguments" in EXPLORE_OPT:
        index = 1
        for arg, length in EXPLORE_OPT["Arguments"].items():
            argv.append(claripy.BVS("argv" + str(index), int(str(length), 0) * 8))
            index += 1

    if "Raw Binary" in EXPLORE_OPT:
        for bin_option, data in EXPLORE_OPT["Raw Binary"].items():
            if bin_option == "Arch":
                arch = data
            if bin_option == "Base":
                base_address = int(str(data), 0)
        p = angr.Project(EXPLORE_OPT["binary_file"],
                         load_options={'main_opts': {'backend': 'blob', 'arch': arch,
                                                     'base_addr': base_address}, 'auto_load_libs': EXPLORE_OPT["auto_load_libs"]})
    else:
        p = angr.Project(EXPLORE_OPT["binary_file"], load_options={"auto_load_libs": EXPLORE_OPT["auto_load_libs"]})

    global REGISTERS
    REGISTERS = p.arch.default_symbolic_registers

    p.hook_symbol('atoi', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    if len(argv) > 1:
        state = p.factory.entry_state(args=argv)
    elif "blank_state" in locals():
        state = p.factory.blank_state(addr=blank_state)
    else:
        state = p.factory.entry_state()

    # Store symbolic vectors in memory
    if "Memory" in EXPLORE_OPT:
        Memory = {}
        for addr, length in EXPLORE_OPT["Memory"].items():
            symbmem_addr = int(addr, 16)
            symbmem_len = int(length, 0)
            Memory.update({symbmem_addr: symbmem_len})
            symb_vector = claripy.BVS('input', symbmem_len * 8)
            state.memory.store(symbmem_addr, symb_vector)

    # Write to memory
    if "Store" in EXPLORE_OPT:
        for addr, value in EXPLORE_OPT["Store"].items():
            store_addr = int(addr, 16)
            store_value = int(value, 16)
            store_length = len(value) - 2
            state.memory.store(store_addr, state.solver.BVV(store_value, 4 * store_length))

    # Handle Symbolic Registers
    if "Registers" in EXPLORE_OPT:
        for register, data in EXPLORE_OPT["Registers"].items():
            if "sv" in data:
                symbvector_length = int(data[2:], 0)
                symbvector = claripy.BVS('symvector', symbvector_length * 8)
                SYMVECTORS.append(symbvector)
                data = symbvector
            else:
                data = int(str(data), 0)
            for REG in REGISTERS:
                if REG == register:
                    setattr(state.regs, register, data)
                    break

    # Handle Hooks
    if "Hooks" in EXPLORE_OPT:
        for object in EXPLORE_OPT["Hooks"]:
            for frame in object.items():
                hook_address = frame[0]
                for option, data in frame[1].items():
                    data = int(str(data), 0)
                    if option == "Length":
                        hook_length = data
                        break
                p.hook(int(hook_address, 16), hook_function, length=hook_length)

    simgr = p.factory.simulation_manager(state)
    if "avoid" in locals():
        simgr.use_technique(angr.exploration_techniques.Explorer(find=find, avoid=avoid))
    else:
        simgr.use_technique(angr.exploration_techniques.Explorer(find=find))


    bin_name = EXPLORE_OPT["binary_file"]

    cfg = None
    vfg = None
    ddg = None
    vsa_ddg = None
    # cfg = unpickle_cfg(bin_name)
    if cfg is None:
        # cfg = p.analyses.CFG(normalize=True)
        # cfg = p.analyses.CFGFast()
        #starts=?
        # cfg = p.analyses.CFGEmulated(keep_state=True)
        cfg = p.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=10, normalize=True)
    main = cfg.functions.function(name="main")

    # vfg = unpickle_vfg(bin_name)
    if vfg is None:
        vfg = p.analyses.VFG(
            cfg,
            start=main.addr,
            context_sensitivity_level=10,
            interfunction_level=10,
            record_function_final_states=True,
            remove_options={angr.options.OPTIMIZE_IR}
        )
    # vsa_ddg = p.analyses.VSA_DDG(vfg=vfg, keep_data=True, start_addr=vfg._start)
    ddg = p.analyses.DDG(cfg)

    print(" ")

    # print_vfg(vfg)


    # target_instr = 0x4011FF
    # target_instr = 0x401194
    # target_instr = 0x40123A
    # target_instr = 0x401246
    target_instr = 0x401208
    # target_reg = "rdi"
    target_reg = "rax"
    target_offset = -8
    target_mem = 0x7fffffffffefef0 + target_offset

    # target_instr = 0x401246
    # target_reg = "edi"

    get_reg_at_instr(cfg, vfg, target_instr, target_reg)
    # get_reg_offset_at_instr(vfg, target_instr, "rbp", target_offset, "int")


    print("CFG HAS", cfg.graph.number_of_nodes(), "NODES AND", cfg.graph.number_of_edges(), "EDGES")
    print("VFG HAS", vfg.graph.number_of_nodes(), "NODES AND", vfg.graph.number_of_edges(), "EDGES")

    #figure_out_types()


    # print_cfg(cfg)
    # print_vfg(vfg)

    if ddg is not None:
        print(ddg)
        print(ddg.graph)
        print(ddg.graph.number_of_nodes())
        print(ddg.graph.number_of_edges())

    print("==========================")

    if vsa_ddg is not None:
        print(vsa_ddg)
        print(vsa_ddg.graph)
        print(vsa_ddg.graph.number_of_nodes())
        print(vsa_ddg.graph.number_of_edges())

########################################################

    # # vfg1 = p.analyses.VFG()
    # # print(vfg1)
    # # print(vfg1._cfg)
    # # print(vfg1._nodes)
    # # print(vfg1.final_states)
    # # print(vfg1._final_address)
    # # simgr.run()
    # # vfg = p.analyses.VFG()
    # # print("--------------------")
    # print(vfg)
    # print(vfg._cfg)
    # print(vfg.final_states)
    # print(vfg._final_address)
    # print(vfg._nodes)
    # print(len(vfg._nodes))
    # for key in vfg._nodes:
    #     print(key)
    #     print("=========")
    #     print(vfg._nodes[key])
    #     print("=========")
    #     print(vfg._nodes[key].final_states)
    #     print(len(vfg._nodes[key].final_states))
    #     print("+++++")
    # print(" ")
    # # ddg = p.analyses.VSA_DDG(start_addr=vfg._start)
    # print(ddg)
    # print(ddg._vfg)
    # print(ddg.graph.number_of_nodes())
    # print(vfg._start)






    simgr.run()
    if simgr.found:
        found_path = simgr.found[0]

        win_sequence = ""
        for win_block in found_path.history.bbl_addrs.hardcopy:
            win_block = p.factory.block(win_block)
            addresses = win_block.instruction_addrs
            for address in addresses:
                win_sequence += hex(address) + ","
        win_sequence = win_sequence[:-1]
        # print("Trace:" + win_sequence)

        if len(argv) > 1:
            for i in range(1, len(argv)):
                print("argv[{id}] = {solution}".format(id=i, solution=found_path.solver.eval(argv[i], cast_to=bytes)))

        if "Memory" in locals() and len(Memory) != 0:
            for address, length in Memory.items():
                print("{addr} = {value}".format(addr=hex(address),
                                                value=found_path.solver.eval(found_path.memory.load(address, length),
                                                                             cast_to=bytes)))

        if len(SYMVECTORS) > 0:
            for SV in SYMVECTORS:
                print(found_path.solver.eval(SV, cast_to=bytes))

        found_stdins = found_path.posix.stdin.content
        if len(found_stdins) > 0:
            std_id = 1
            for stdin in found_stdins:
                print(
                    "stdin[{id}] = {solution}".format(id=std_id,
                                                      solution=found_path.solver.eval(stdin[0], cast_to=bytes)))
                std_id += 1
    else:
        print("")

    # pickle_cfg(cfg, bin_name)
    # pickle_vfg(vfg, bin_name)

    elapsed = time.process_time() - t_0
    print("ELAPSED: ", elapsed)
    return


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: *thisScript.py* angr_options.json")
        exit()
    file = sys.argv[1]
    main(file)
