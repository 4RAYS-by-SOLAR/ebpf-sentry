
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

# String patterns:

# BPF_LD_IMM64 / BPF_MOV64_IMM
# BPF_STX_MEM
# BPF_LD_IMM64 / BPF_MOV64_IMM
# BPF_STX_MEM
# <ANOTHER INSTRUCTION>

# BPF_LD_IMM64 / BPF_MOV64_IMM
# BPF_STX_MEM
# BPF_STX_MEM
# BPF_STX_MEM
# <ANOTHER INSTRUCTION>

# BPF_LDX_MEM(BPF_B, BPF_REG_ARG1, BPF_REG_FP, -40)
# BPF_JMP_IMM(BPF_JNE, BPF_REG_ARG1, 115, 2)
# BPF_LDX_MEM
# BPF_JMP_IMM
#...

def parse_imm_as_string(imm):
    imm_hex = format(imm, 'x')
    if len(imm_hex) % 2 == 1:
        imm_hex = '0' + imm_hex
    imm_hex_rev = "".join(reversed([imm_hex[i:i+2] for i in range(0, len(imm_hex), 2)]))
    try:
        imm_str = bytearray.fromhex(imm_hex_rev).decode()
    except:
        imm_str = imm_hex
        pass
    return imm_str

def get_insn_type(insn):
    return insn['insn_params']['type']

def get_insn_params(insn):
    return insn['insn_params']

def parse_mov64_imm(insns_list, start_index):
    ret_str = ''
    index = start_index
    current_insn_params = get_insn_params(insns_list[index])
    tmp_str = parse_imm_as_string(current_insn_params['imm'])
    ret_str = tmp_str
    index = index + 2
    while True:
        if (get_insn_type(insns_list[index]) == 'BPF_LD_IMM64') and (get_insn_type(insns_list[index+2]) == 'BPF_STX_MEM'):
            current_insn_params = get_insn_params(insns_list[index])
            first_part = parse_imm_as_string(current_insn_params['imm'])
            next_insn_params = get_insn_params(insns_list[index+1])
            second_part = parse_imm_as_string(next_insn_params['imm'])
            tmp_str = first_part + second_part
            ret_str = tmp_str + ret_str
            index = index + 3
        elif (get_insn_type(insns_list[index])== 'BPF_MOV64_IMM') and (get_insn_type(insns_list[index+1]) == 'BPF_STX_MEM'):
            current_insn_params = get_insn_params(insns_list[index])
            tmp_str = parse_imm_as_string(current_insn_params['imm'])
            ret_str = tmp_str + ret_str
            index = index + 2
        elif (get_insn_type(insns_list[index]) == 'BPF_STX_MEM'):
            ret_str = tmp_str + ret_str
            index = index + 1
        else:
            break
    return ret_str, index

def parse_ld_imm64(insns_list, start_index):
    ret_str = ''
    index = start_index
    current_insn_params = get_insn_params(insns_list[index])
    first_part = parse_imm_as_string(current_insn_params['imm'])
    next_insn_params = get_insn_params(insns_list[index+1])
    second_part = parse_imm_as_string(next_insn_params['imm'])
    tmp_str = first_part + second_part
    ret_str = tmp_str
    index = index + 3
    while True:
        if (get_insn_type(insns_list[index]) == 'BPF_LD_IMM64') and (get_insn_type(insns_list[index+2]) == 'BPF_STX_MEM'):
            current_insn_params = get_insn_params(insns_list[index])
            first_part = parse_imm_as_string(current_insn_params['imm'])
            next_insn_params = get_insn_params(insns_list[index+1])
            second_part = parse_imm_as_string(next_insn_params['imm'])
            tmp_str = first_part + second_part
            ret_str = tmp_str + ret_str
            index = index + 3
        elif (get_insn_type(insns_list[index])== 'BPF_MOV64_IMM') and (get_insn_type(insns_list[index+1]) == 'BPF_STX_MEM'):
            current_insn_params = get_insn_params(insns_list[index])
            tmp_str = parse_imm_as_string(current_insn_params['imm'])
            ret_str = tmp_str + ret_str
            index = index + 2
        elif (get_insn_type(insns_list[index]) == 'BPF_STX_MEM'):
            ret_str = tmp_str + ret_str
            index = index + 1
        else:
            break
    return ret_str, index

# Find all patterns and pass them to functions for parsing
def insns_postprocessing(insns_list):
    index = 0
    cycle_strings = [] # dicts like {current_offset: <off>, insn_number: <num>, string: <string>}
    strings_list = [] # dicts like {insn_number: <num>, string: <string>}
    while index < len(insns_list):
        current_insn = insns_list[index]
        current_insn_type = get_insn_type(current_insn)
        if (current_insn_type == 'BPF_MOV64_IMM') and (get_insn_type(insns_list[index+1]) == 'BPF_STX_MEM'):
            start_index = index
            tmp_str, index = parse_mov64_imm(insns_list, index)
            strings_list.append({'insn_number': start_index, 'string': tmp_str})
        elif (current_insn_type == 'BPF_LD_IMM64') and (get_insn_type(insns_list[index+2]) == 'BPF_STX_MEM'):
            start_index = index
            tmp_str, index = parse_ld_imm64(insns_list, index)
            strings_list.append({'insn_number': start_index, 'string': tmp_str})
        elif (current_insn_type == 'BPF_LDX_MEM') and (get_insn_type(insns_list[index+1]) == 'BPF_JMP_IMM'):
            start_index = index
            current_insn_params = get_insn_params(insns_list[index])
            current_off = current_insn_params['off']
            next_insn_params = get_insn_params(insns_list[index+1])
            next_imm = parse_imm_as_string(next_insn_params['imm'])
            offset_seen = False
            if len(cycle_strings) == 0:
                cycle_strings.append({'current_offset': current_off, 'insn_number': start_index, 'string': next_imm})
                offset_seen = True
            else:
                for cycle_str in cycle_strings:
                    if abs(cycle_str['current_offset'] - current_off) == 1:
                        offset_seen = True
                        cycle_str['current_offset'] = current_off
                        cycle_str['string'] = cycle_str['string'] + next_imm
                        break
            if offset_seen == False:
                cycle_strings.append({'current_offset': current_off, 'insn_number': start_index, 'string': next_imm})
                offset_seen = True
            index = index + 2
        else:
            index = index + 1
    for cycle_str in cycle_strings:
        strings_list.append({'insn_number': cycle_str['insn_number'], 'string': cycle_str['string']})
    return strings_list

def print_insns(insns_list):
    for insn in insns_list:
        print(insn['parsed_insn'])
