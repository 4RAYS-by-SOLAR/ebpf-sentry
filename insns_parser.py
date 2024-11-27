import re

# BPF_CLASS(code) ((code) & 0x07)
BPF_CLASS = {
    "BPF_LD":0x00,
    "BPF_LDX":0x01,
    "BPF_ST":0x02,
    "BPF_STX":0x03,
    "BPF_ALU":0x04,
    "BPF_JMP":0x05,
    #"BPF_RET":0x06,
    "BPF_JMP32":0x06,
    #"BPF_MISC":0x07
    "BPF_ALU64":0x07
}

#define BPF_SRC(code)   ((code) & 0x08)
BPF_SRC = {
    "BPF_K":0x00,
    "BPF_X":0x08
}

# ld/ldx fields 
# BPF_SIZE(code)  ((code) & 0x18)
BPF_SIZE = {
    "BPF_W":0x00, 
    "BPF_H":0x08,
    "BPF_B":0x10,
    "BPF_DW":0x18
}
# BPF_MODE(code)  ((code) & 0xe0)
BPF_MODE = {
    "BPF_IMM":0x00,
    "BPF_ABS":0x20,
    "BPF_IND":0x40,
    "BPF_MEM":0x60,
    #"BPF_LEN":0x80,
    "BPF_MEMSX":0x80,
    "BPF_MSH":0xa0,
    "BPF_ATOMIC":0xc0
}

# /* alu/jmp fields */
# BPF_OP(code)    ((code) & 0xf0)
BPF_OP_ALU = {
    "BPF_ADD":0x00,
    "BPF_SUB":0x10,
    "BPF_MUL":0x20,
    "BPF_DIV":0x30,
    "BPF_OR":0x40,
    "BPF_AND":0x50,
    "BPF_LSH":0x60,
    "BPF_RSH":0x70,
    "BPF_NEG":0x80,
    "BPF_MOD":0x90,
    "BPF_XOR":0xa0,
    "BPF_MOV":0xb0,
    "BPF_ARSH":0xc0,
    "BPF_END":0xd0
}
BPF_OP_JMP = {
    "BPF_JA":0x00,
    "BPF_JEQ":0x10,
    "BPF_JGT":0x20,
    "BPF_JGE":0x30,
    "BPF_JSET":0x40,
    "BPF_JNE":0x50,	
    "BPF_JLT":0xa0,	
    "BPF_JLE":0xb0,	
    "BPF_JSGT":0x60,
    "BPF_JSGE":0x70,
    "BPF_JSLT":0xc0,
    "BPF_JSLE":0xd0,
    "BPF_JCOND":0xe0,
    "BPF_CALL":0x80,
    "BPF_EXIT":0x90	
}

BPF_REGS = {
    "BPF_REG_ARG1":0x1,
    "BPF_REG_ARG2":0x2,
    "BPF_REG_ARG3":0x3,
    "BPF_REG_ARG4":0x4,
    "BPF_REG_ARG5":0x5,
    "BPF_REG_CTX":0x6,
    "BPF_REG_FP":0xa,
    # /* Additional register mappings for converted user programs. */
    "BPF_REG_A":0x0,
    "BPF_REG_X":0x7,
    "BPF_REG_TMP":0x2,	# /* scratch reg */
    "BPF_REG_D":0x8,	# /* data, callee-saved */
    "BPF_REG_H":0x9 	# /* hlen, callee-saved */    
}

def parse_reg(reg):
    for name, val in BPF_REGS.items():
        if val == reg:
            return name    

def parse_bpf_op(code, insn_type):
    code = code & 0xf0
    if insn_type == "alu":
        for name, val in BPF_OP_ALU.items():
            if val == code:
                return name
    elif insn_type == "jmp":
        for name, val in BPF_OP_JMP.items():
            if val == code:
                return name        


def parse_bpf_size(code):
    code = code & 0x18
    for name, val in BPF_SIZE.items():
        if val == code:
            return name    

def parse_insn(insn, func_list):
    code = insn["code"]
    reg = insn["reg"]
    off = insn["off"]
    imm = insn["imm"]
    
    src_reg_mask = 0b11110000
    dst_reg_mask = 0b00001111
    dst_reg = reg & dst_reg_mask
    src_reg = (reg & src_reg_mask) >> 4

    bpf_class_val = code & 0x07
    for name, val in BPF_CLASS.items():
        if val == bpf_class_val:
            bpf_class_name = name
            break
    
    parsed_insn = {}
    if code == 0:
        insn_proto = "BPF_LD_IMM64_RAW_2({0})"
        insn_type = "BPF_LD_IMM64_RAW_2"
        insn_params = {'type': insn_type, 'imm': imm}
        insn_parsed = insn_proto.format(str(imm))

    if bpf_class_name == "BPF_LD":
        if (code & 0x18) == BPF_SIZE["BPF_DW"]:
            if (code & 0xe0) == BPF_MODE["BPF_IMM"]:
                if src_reg == 1: # BPF_PSEUDO_MAP_FD
                    insn_proto = "BPF_LD_MAP_FD({0}, {1}, {2})"
                    insn_type = "BPF_LD_MAP_FD"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = "BPF_PSEUDO_MAP_FD"
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(dst_reg_name, src_reg_name, str(imm))
                elif src_reg == 0: # BPF_LD_IMM64
                    insn_proto = "BPF_LD_IMM64({0}, {1})"
                    insn_type = "BPF_LD_IMM64"
                    dst_reg_name = parse_reg(dst_reg)
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(dst_reg_name, str(imm))                   
                else:
                    insn_proto = "BPF_LD_IMM64_RAW({0}, {1}, {2})"
                    insn_type = "BPF_LD_IMM64_RAW"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(dst_reg_name, src_reg_name, str(imm))
        elif (code & 0xe0) == BPF_MODE['BPF_ABS']:
            op_size = parse_bpf_size(code)
            insn_proto = "BPF_LD_ABS({0}, {1})"
            insn_type = "BPF_LD_ABS"
            insn_params = {'type': insn_type, 'op_size': op_size, 'imm': imm}
            insn_parsed = insn_proto.format(op_size, str(imm))
        elif (code & 0xe0) == BPF_MODE['BPF_IND']:
            op_size = parse_bpf_size(code)
            src_reg_name = parse_reg(src_reg)
            insn_proto = "BPF_LD_IND({0}, {1}, {2})"
            insn_type = "BPF_LD_IND"
            insn_params = {'type': insn_type, 'op_size': op_size, 'src_reg': src_reg_name, 'imm': imm}
            insn_parsed = insn_proto.format(op_size, src_reg_name, str(imm))

    elif bpf_class_name == "BPF_LDX":
        op_size = parse_bpf_size(code)
        if (code & 0xe0) == BPF_MODE['BPF_MEM']:
            insn_proto = "BPF_LDX_MEM({0}, {1}, {2}, {3})"
            insn_type = "BPF_LDX_MEM"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            op_size = parse_bpf_size(code)
            insn_params = {'type': insn_type, 'op_size': op_size, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
            insn_parsed = insn_proto.format(op_size, dst_reg_name, src_reg_name, str(off))
        elif (code & 0xe0) == BPF_MODE['BPF_MEMSX']:
            insn_proto = "BPF_LDX_MEMSX({0}, {1}, {2}, {3})"
            insn_type = "BPF_LDX_MEMSX"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            op_size = parse_bpf_size(code)
            insn_params = {'type': insn_type, 'op_size': op_size, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
            insn_parsed = insn_proto.format(op_size, dst_reg_name, src_reg_name, str(off))

    elif bpf_class_name == "BPF_ST":
        op_size = parse_bpf_size(code)
        if (code & 0xe0) == BPF_MODE['BPF_MEM']:
            insn_proto = "BPF_ST_MEM({0}, {1}, {2}, {3})"
            insn_type = "BPF_ST_MEM"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            op_size = parse_bpf_size(code)
            insn_params = {'type': insn_type, 'op_size': op_size, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
            insn_parsed = insn_proto.format(op_size, dst_reg_name, src_reg_name, str(imm))

    elif bpf_class_name == "BPF_STX":
        op_size = parse_bpf_size(code)
        if (code & 0xe0) == BPF_MODE['BPF_MEM']:
            insn_proto = "BPF_STX_MEM({0}, {1}, {2}, {3})"
            insn_type = "BPF_STX_MEM"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            op_size = parse_bpf_size(code)
            insn_params = {'type': insn_type, 'op_size': op_size, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
            insn_parsed = insn_proto.format(op_size, dst_reg_name, src_reg_name, str(off))
        elif (code & 0xe0) == BPF_MODE['BPF_ATOMIC']:
            insn_proto = "BPF_ATOMIC_OP({0}, {1}, {2}, {3}, {4})"
            insn_type = "BPF_ATOMIC_OP"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            op_size = parse_bpf_size(code)
            insn_params = {'type': insn_type, 'op_size': op_size, 'op': imm, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
            insn_parsed = insn_proto.format(op_size, str(imm), dst_reg_name, src_reg_name, str(off))

    elif bpf_class_name == "BPF_ALU":
        if (code & 0xf0) == BPF_OP_ALU['BPF_MOV']:
            if dst_reg != 0 and src_reg != 0 and imm != 0:
                if (code & 0x08) == BPF_SRC['BPF_X']:
                    insn_proto = "BPF_MOV32_RAW({0}, {1}, {2}, {3})"
                    insn_type = "BPF_MOV32_RAW"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    bpf_src = "BPF_X"
                    insn_params = {'type': insn_type, 'bpf_src': bpf_src, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(bpf_src, dst_reg_name, src_reg_name, str(imm))
                elif (code & 0x08) == BPF_SRC['BPF_K']:
                    insn_proto = "BPF_MOV32_RAW({0}, {1}, {2}, {3})"
                    insn_type = "BPF_MOV32_RAW"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    bpf_src = "BPF_K"
                    insn_params = {'type': insn_type, 'bpf_src': bpf_src, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(bpf_src, dst_reg_name, src_reg_name, str(imm))
            if (code & 0x08) == BPF_SRC['BPF_X']:
                if off == 0:
                    if imm == 0:
                        insn_proto = "BPF_MOV32_REG({0}, {1})"
                        insn_type = "BPF_MOV32_REG"
                        dst_reg_name = parse_reg(dst_reg)
                        src_reg_name = parse_reg(src_reg)
                        insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name}
                        insn_parsed = insn_proto.format(dst_reg_name, src_reg_name)
                    elif imm == 1:
                        insn_proto = "BPF_ZEXT_REG({0})"
                        insn_type = "BPF_ZEXT_REG"
                        dst_reg_name = parse_reg(dst_reg)
                        insn_params = {'type': insn_type, 'dst_reg': dst_reg_name}
                        insn_parsed = insn_proto.format(dst_reg_name)
                else:
                    insn_proto = "BPF_MOVSX32_REG({0}, {1}, {2})"
                    insn_type = "BPF_MOVSX32_REG"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
                    insn_parsed = insn_proto.format(dst_reg_name, src_reg_name, str(off))                   
            elif (code & 0x08) == BPF_SRC['BPF_K']:
                insn_proto = "BPF_MOV32_IMM({0}, {1})"
                insn_type = "BPF_MOV32_IMM"
                dst_reg_name = parse_reg(dst_reg)
                insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'imm': imm}
                insn_parsed = insn_proto.format(dst_reg_name, str(imm))
        elif (code & 0xf0) == BPF_OP_ALU['BPF_END']:
            if (code & 0x08) == BPF_SRC['BPF_X']:
                insn_proto = "BPF_ENDIAN({0}, {1}, {2})"
                insn_type = "BPF_ENDIAN"
                dst_reg_name = parse_reg(dst_reg)
                bpf_src ="BPF_X"
                insn_parsed = insn_proto.format(bpf_src, dst_reg_name, str(imm))   
            elif (code & 0x08) == BPF_SRC['BPF_K']:
                insn_proto = "BPF_ENDIAN({0}, {1}, {2})"
                insn_type = "BPF_ENDIAN"
                dst_reg_name = parse_reg(dst_reg)
                bpf_src ="BPF_K"
                insn_parsed = insn_proto.format(bpf_src, dst_reg_name, str(imm))    
            insn_params = {'type': insn_type, 'bpf_src': bpf_src, 'dst_reg': dst_reg_name, 'imm': imm}       
        else:
            op_code = parse_bpf_op(code, "alu")
            if (code & 0x08) == BPF_SRC['BPF_X']:
                if off != 0:
                    insn_proto = "BPF_ALU32_REG_OFF({0}, {1}, {2}, {3})"
                    insn_type = "BPF_ALU32_REG_OFF"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, src_reg_name, str(off))
                else:
                    insn_proto = "BPF_ALU32_REG({0}, {1}, {2})"
                    insn_type = "BPF_ALU32_REG"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, src_reg_name)
            elif (code & 0x08) == BPF_SRC['BPF_K']:
                if off != 0:
                    insn_proto = "BPF_ALU32_IMM_OFF({0}, {1}, {2}, {3})"
                    insn_type = "BPF_ALU32_IMM_OFF"
                    dst_reg_name = parse_reg(dst_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'imm': imm, 'off': off}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, str(imm), str(off))
                elif off == 0:
                    insn_proto = "BPF_ALU32_IMM({0}, {1}, {2})"
                    insn_type = "BPF_ALU32_IMM"
                    dst_reg_name = parse_reg(dst_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, str(imm))                    

    elif bpf_class_name == "BPF_JMP":
        op_code = parse_bpf_op(code, "jmp")
        if (code & 0xf0) == BPF_OP_JMP['BPF_JA']:
            insn_proto = "BPF_JMP_A({0})"
            insn_type = "BPF_JMP_A"
            insn_params = {'type': insn_type, 'off': off}
            insn_parsed = insn_proto.format(str(off))
        elif (code & 0xf0) == BPF_OP_JMP['BPF_CALL']:
            if src_reg == 1: # BPF_PSEUDO_CALL
                insn_proto = "BPF_CALL_REL({0})"
                insn_type = "BPF_CALL_REL"
                insn_params = {'type': insn_type, 'imm': imm}
                insn_parsed = insn_proto.format(str(imm))
            else:
                insn_proto = "BPF_EMIT_CALL({0})"
                insn_type = "BPF_EMIT_CALL"
                func_name = func_list[imm]
                insn_params = {'type': insn_type, 'func': func_name}
                insn_parsed = insn_proto.format(func_name)
        elif (code & 0xf0) == BPF_OP_JMP['BPF_EXIT']:
            insn_proto = "BPF_EXIT_INSN()"
            insn_type = "BPF_EXIT_INSN"
            insn_params = {'type': insn_type}
            insn_parsed = insn_proto   
        elif (code & 0x08) == BPF_SRC['BPF_K']:
            insn_proto = "BPF_JMP_IMM({0}, {1}, {2}, {3})"
            insn_type = "BPF_JMP_IMM"
            dst_reg_name = parse_reg(dst_reg)
            insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'imm': imm, 'off': off}
            insn_parsed = insn_proto.format(op_code, dst_reg_name, str(imm), str(off))
        elif (code & 0x08) == BPF_SRC['BPF_X']:
            insn_proto = "BPF_JMP_REG({0}, {1}, {2}, {3})"
            insn_type = "BPF_JMP_REG"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
            insn_parsed = insn_proto.format(op_code, dst_reg_name, src_reg_name, str(off))

    elif bpf_class_name == "BPF_JMP32":
        op_code = parse_bpf_op(code, "jmp")
        if (code & 0x08) == BPF_SRC['BPF_K']:
            insn_proto = "BPF_JMP32_IMM({0}, {1}, {2}, {3})"
            insn_type = "BPF_JMP32_IMM"
            dst_reg_name = parse_reg(dst_reg)
            insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'imm': imm, 'off': off}
            insn_parsed = insn_proto.format(op_code, dst_reg_name, str(imm), str(off))
        elif (code & 0x08) == BPF_SRC['BPF_X']:
            insn_proto = "BPF_JMP32_REG({0}, {1}, {2}, {3})"
            insn_type = "BPF_JMP32_REG"
            dst_reg_name = parse_reg(dst_reg)
            src_reg_name = parse_reg(src_reg)
            insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
            insn_parsed = insn_proto.format(op_code, dst_reg_name, src_reg_name, str(off))

    elif bpf_class_name == "BPF_ALU64":
        if (code & 0xf0) == BPF_OP_ALU['BPF_MOV']:
            if dst_reg != 0 and src_reg != 0 and imm != 0:
                if (code & 0x08) == BPF_SRC['BPF_X']:
                    insn_proto = "BPF_MOV64_RAW({0}, {1}, {2}, {3})"
                    insn_type = "BPF_MOV64_RAW"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    bpf_src = "BPF_X"
                    insn_params = {'type': insn_type, 'bpf_src': bpf_src, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(bpf_src, dst_reg_name, src_reg_name, str(imm))   
                elif (code & 0x08) == BPF_SRC['BPF_K']:
                    insn_proto = "BPF_MOV64_RAW({0}, {1}, {2}, {3})"
                    insn_type = "BPF_MOV64_RAW"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    bpf_src = "BPF_K"
                    insn_params = {'type': insn_type, 'bpf_src': bpf_src, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(bpf_src, dst_reg_name, src_reg_name, str(imm))                  
            if (code & 0x08) == BPF_SRC['BPF_X']:
                if off == 0:
                    insn_proto = "BPF_MOV64_REG({0}, {1})"
                    insn_type = "BPF_MOV64_REG"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name}
                    insn_parsed = insn_proto.format(dst_reg_name, src_reg_name)
                elif off == -1: # BPF_ADDR_PERCPU
                    insn_proto = "BPF_MOV64_PERCPU_REG({0}, {1})"
                    insn_type = "BPF_MOV64_PERCPU_REG"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name}
                    insn_parsed = insn_proto.format(dst_reg_name, src_reg_name)                    
                else:
                    insn_proto = "BPF_MOVSX64_REG({0}, {1}, {2})"
                    insn_type = "BPF_MOVSX64_REG"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
                    insn_parsed = insn_proto.format(dst_reg_name, src_reg_name, str(off))                   
            elif (code & 0x08) == BPF_SRC['BPF_K']:
                insn_proto = "BPF_MOV64_IMM({0}, {1})"
                insn_type = "BPF_MOV64_IMM"
                dst_reg_name = parse_reg(dst_reg)
                insn_params = {'type': insn_type, 'dst_reg': dst_reg_name, 'imm': imm}
                insn_parsed = insn_proto.format(dst_reg_name, str(imm))      
        else:
            op_code = parse_bpf_op(code, "alu")
            if (code & 0x08) == BPF_SRC['BPF_X']:
                if off != 0:
                    insn_proto = "BPF_ALU64_REG_OFF({0}, {1}, {2}, {3})"
                    insn_type = "BPF_ALU64_REG_OFF"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name, 'off': off}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, src_reg_name, str(off))
                else:
                    insn_proto = "BPF_ALU64_REG({0}, {1}, {2})"
                    insn_type = "BPF_ALU64_REG"
                    dst_reg_name = parse_reg(dst_reg)
                    src_reg_name = parse_reg(src_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'src_reg': src_reg_name}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, src_reg_name)
            elif (code & 0x08) == BPF_SRC['BPF_K']:
                if off != 0:
                    insn_proto = "BPF_ALU64_IMM_OFF({0}, {1}, {2}, {3})"
                    insn_type = "BPF_ALU64_IMM_OFF"
                    dst_reg_name = parse_reg(dst_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'imm': imm, 'off': off}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, str(imm), str(off))
                elif off == 0:
                    insn_proto = "BPF_ALU64_IMM({0}, {1}, {2})"
                    insn_type = "BPF_ALU64_IMM"
                    dst_reg_name = parse_reg(dst_reg)
                    insn_params = {'type': insn_type, 'op_code': op_code, 'dst_reg': dst_reg_name, 'imm': imm}
                    insn_parsed = insn_proto.format(op_code, dst_reg_name, str(imm))                       
    
    insn_new = insn
    insn_new.update({"parsed_insn": insn_parsed})
    insn_new.update({'insn_params': insn_params})
    return insn_new


def parse_insns_list(insns_list, func_list):
    parsed_insns_list = []
    for insn in insns_list:
        parsed_insn = parse_insn(insn, func_list)
        parsed_insns_list.append(parsed_insn)
    return parsed_insns_list

def get_func_numbers():
    bpfh_file_path = '/usr/include/linux/bpf.h'
    bpfh_file = open(bpfh_file_path, 'r')
    bpfh_text = bpfh_file.read()
    bpfh_file.close()
    regexp_fn = 'FN\((.*)\),\t*\\\\'
    fn_matches = re.findall(regexp_fn, bpfh_text)
    return fn_matches
