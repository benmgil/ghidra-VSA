import sys
import angr
import claripy
import json
import time
import logging
import pickle
import os.path
from angr.sim_type import ALL_TYPES


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

def get_mem_at_instr(cfg, vfg, target_instr, target_mem, type="int"):
    def mem_getter(state):
        return getattr(state.mem[target_mem], type).resolved
    target_str = "[" + hex(target_mem).upper() + "]"
    get_val_at_instr(cfg, vfg, target_instr, target_str, mem_getter)

def get_reg_offset_at_instr(cfg, vfg, target_instr, target_reg, offset, type="int"):
    def offset_getter(state):
        reg_val = state.regs.get("_"+target_reg)
        return getattr(state.mem[reg_val + offset], type).resolved
    target_str = "[" + target_reg.upper() + " + " + hex(offset) + "]"
    get_val_at_instr(cfg, vfg, target_instr, target_str, offset_getter)




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


def prepare_args(vsa_options, proj):
    try:
        ghidra_base = int(vsa_options["binary_details"]["base"], 16)
        angr_base = proj.loader.min_addr
        analysis_type = vsa_options["target"]

        vsa_args = vsa_options["args"]

        target_instr = int(vsa_args["instruction"], 16)
        target_instr = target_instr + angr_base - ghidra_base

        if analysis_type == "register":
            target_reg = vsa_args["register"]
            return (analysis_type, target_instr, target_reg)

        if analysis_type == "memory":
            target_mem = int(vsa_args["addr"], 16)
            if target_mem is None:
                print("Invalid memory address")
                return None
            target_type = vsa_args["type"]
            if target_type not in ALL_TYPES:
                print("Invalid type")
                return None
            return (analysis_type, target_instr, target_mem, target_type)

        if analysis_type == "offset":
            target_reg = vsa_args["register"]
            target_offset = int(vsa_args["offset"], 16)
            if target_offset is None:
                print("Invalid offset value")
                return None

            target_type = vsa_args["type"]
            if target_type not in ALL_TYPES:
                print("Invalid type")
                return None
            return (analysis_type, target_instr, target_reg, target_offset, target_type)

        return None
    except Exception as e:
        print("INVALID ARGS FROM GHIDRA")
        print(e)
        return None




def do_vsa(cfg, vfg, args):
    analysis_type = args[0]
    fun_args = args[1:]

    if analysis_type == "register":
        get_reg_at_instr(cfg, vfg, *fun_args)
    if analysis_type == "memory":
        get_mem_at_instr(cfg, vfg, *fun_args)
    if analysis_type == "offset":
        get_reg_offset_at_instr(cfg, vfg, *fun_args)



def main(file):
    t_0 = time.process_time()
    logging.getLogger('angr.storage.memory_mixins.default_filler_mixin').setLevel('ERROR')

    try:
        with open(file, encoding='utf-8') as json_file:
            global vsa_options
            vsa_options = json.load(json_file)
    except:
        print("Could not open file", file)



    binary_file = vsa_options["binary_file"]


    # if "binary_details" in vsa_options:
    #     for detail, data in vsa_options["binary_details"].items():
    #         if detail == "arch":
    #             arch = data
    #         if detail == "base":
    #             base_address = int(str(data), 0)
    #     p = angr.Project(binary_file,
    #                      load_options={'main_opts': {'backend': 'blob', 'arch': arch,
    #                                                  'base_addr': base_address}, 'auto_load_libs': 'False'})
    # else:
    #     p = angr.Project(vsa_options["binary_file"], load_options={'auto_load_libs': 'False'})
    p = angr.Project(vsa_options["binary_file"], load_options={'auto_load_libs': 'False'})

    p.hook_symbol('atoi', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    # if len(argv) > 1:
    #     state = p.factory.entry_state(args=argv)
    # else:
    #     state = p.factory.entry_state()
    state = p.factory.entry_state()
    simgr = p.factory.simulation_manager(state)

    # print(hex(p.loader.min_addr)) #correct
    # print(hex(p.loader.main_object.min_addr)) #correct
    # print(hex(p.loader.main_object.linked_base)) #0x0
    # print(hex(p.loader.main_object.mapped_base)) #correct


    cfg = None
    vfg = None
    ddg = None
    vsa_ddg = None
    # cfg = unpickle_cfg(binary_file)
    if cfg is None:
        # cfg = p.analyses.CFG(normalize=True)
        # cfg = p.analyses.CFGFast()
        #starts=?
        # cfg = p.analyses.CFGEmulated(keep_state=True)
        cfg = p.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=10, normalize=True)

    main_addr = cfg.functions.function(name="main")

    # vfg = unpickle_vfg(binary_file)
    if vfg is None:
        vfg = p.analyses.VFG(
            cfg,
            start=main_addr.addr,
            context_sensitivity_level=10,
            interfunction_level=10,
            record_function_final_states=True,
            remove_options={angr.options.OPTIMIZE_IR}
        )
    # vsa_ddg = p.analyses.VSA_DDG(vfg=vfg, keep_data=True, start_addr=vfg._start)
    # ddg = p.analyses.DDG(cfg)

    # print(" ")
    args = prepare_args(vsa_options, p)
    if args is None:
        return
    do_vsa(cfg, vfg, args)




    # # target_instr = 0x4011FF
    # # target_instr = 0x401194
    # # target_instr = 0x40123A
    # # target_instr = 0x401246
    # target_instr = 0x401208
    # # target_reg = "rdi"
    # target_reg = "rax"
    # target_offset = -8
    # target_mem = 0x7fffffffffefef0 + target_offset
    #
    # # target_instr = 0x401246
    # # target_reg = "edi"
    #
    # get_reg_at_instr(cfg, vfg, target_instr, target_reg)
    # # get_reg_offset_at_instr(vfg, target_instr, "rbp", target_offset, "int")


    # print("CFG HAS", cfg.graph.number_of_nodes(), "NODES AND", cfg.graph.number_of_edges(), "EDGES")
    # print("VFG HAS", vfg.graph.number_of_nodes(), "NODES AND", vfg.graph.number_of_edges(), "EDGES")

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



    # pickle_cfg(cfg, binary_file)
    # pickle_vfg(vfg, binary_file)

    elapsed = time.process_time() - t_0
    print("ELAPSED: ", elapsed)
    return


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: *thisScript.py* angr_options.json")
        exit()
    file = sys.argv[1]
    main(file)
