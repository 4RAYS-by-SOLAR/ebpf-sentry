def generatecode(detectname):
    bpftext = """
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bcc/helpers.h>
#include <bcc/proto.h> 
#include <linux/sched.h>
#include <uapi/linux/if_packet.h>
#include <linux/version.h>
#include <linux/log2.h>
#include <asm/page.h>

#define MAX_INSN_COUNT 2000
#define MAX_FUNC_NAME_LEN 32
#define MAX_PROG_FULL_NAME 128
#define PROG_LIMITS_COUNT 3
#define MAXLOOP 20

BPF_PROG_ARRAY(prog_array, 10);

//two buffer for output
BPF_PERF_OUTPUT(generic_info);
BPF_PERF_OUTPUT(instructions);

// general information about the ebpf program
struct gen_info {
	u32 random_id;
	u32 pid;
	char comm[TASK_COMM_LEN];
	char prog_name[MAX_PROG_FULL_NAME];
	int cmd;
	u32 prog_type;
	u32 insn_cnt;
	u32 log_size;
};

// each ebpf program instruction
struct correct_types {
	u32 random_id;
	u32 insn_cnt;
	u32 insn_num;
    u8  code;
    u8 reg;
    s16 off;
    int  imm;
    char prog_name[32]; // parse name of bpfprog
};

struct bpf_insn_out {
    u8   code;
    u8   reg;
    s16  off;
    s32  imm;
};

struct filterpattern {
    char helper_name[32];
    u32 count;
};

struct prognamepattern {
    char progname[32];
};

struct helper_limit {
    int current_count; // current number of calls
    u32 max_count;     // maximum number of calls
};

//array of intercepted instructions
BPF_ARRAY(parseArray, struct correct_types, MAX_INSN_COUNT);

//pointer to first instruction for prevent
BPF_ARRAY(insn_ptrs, u64, MAX_INSN_COUNT);

//helpernames patterns
BPF_HASH(helper_limits, u32, struct helper_limit);
BPF_ARRAY(stateimm, u32, MAXLOOP);

//progname patterns
BPF_ARRAY(prognamepattern, struct prognamepattern, MAX_INSN_COUNT);

// string comparison because the header file is not included
static __always_inline int bpf_strcmp(const char *str1, const char *str2, int length) {
    for (int i = 0; i < length; i++) {
        if (str1[i] != str2[i]) {
            return str1[i] - str2[i];
        }

        if (str1[i] == 0x00 && str2[i] == 0x00) {
            if (i > 1){
                return 0;
            }
            else {
                return 1;
            }
        }
    }
    return 0;
}

//addpatterns to block the prog, generated automatically
int filtersInit(struct pt_regs *ctx) {

    struct helper_limit limit;
    u32 key;

    FUNCLIMITPATTERNGENERATOR

    u32 pattern_key;

    PROGNAMEFILTERPATTERN

    prog_array.call(ctx, 3);
    
    return 0;
}


int funcPatternfilter(struct pt_regs *ctx) {

    u32 count = MAX_INSN_COUNT;
   
    //get 133 instructions
    u32 counterr = 0;
    for (u32 i = 0; i < count; i++) {
        u32 key = i;
        struct correct_types *currentfields = parseArray.lookup(&key);
        if (!currentfields || currentfields->insn_num >= currentfields->insn_cnt) {
            break;
        }

        //if a helper from the pattern is encountered - decrement
        if (currentfields->code == 133) {
            bpf_trace_printk("currentfields->imm: %d", currentfields->imm);
            struct helper_limit *limit = helper_limits.lookup(&currentfields->imm);
            if (!limit){
                stateimm.update(&counterr, &currentfields->imm);
                counterr ++;
                continue;
            }
            else {
                limit->current_count++;
                stateimm.update(&counterr, &currentfields->imm);
                counterr++;
            }
        }
    }

    prog_array.call(ctx, 4);
    return 0; 
}

int funcPatternfilterverdict(struct pt_regs *ctx) {
    bpf_trace_printk("begin");

    u64 *insns_ptr;
    int index = 0;

    insns_ptr = insn_ptrs.lookup(&index);
    if (!insns_ptr) {
        return 0;
    }

    u32 isblock = 1; // default - blocked
    u32 found_valid = 0; // Variable to identify real results obtained

    //check that the occurrences in the pattern are zero
    //If it's zero, it's malware isblock - stay True
    //If not, skip further

    for (u32 i = 0; i < MAXLOOP; i++) {
        u32 key = i;
        u32 *imm = stateimm.lookup(&key); 

        if (!imm) {
            continue; 
        }

        u32 imm_value = *imm; 

        if (imm_value == 0) {
            continue; 
        }

        found_valid = 1;

        struct helper_limit *limit = helper_limits.lookup(&imm_value);
    
        if (!limit) {
            bpf_trace_printk("set isblock = 0 (no limit)");
            isblock = 0;
            break; 
        }

        if (limit->current_count >= limit->max_count) {
            bpf_trace_printk("set isblock = 1 (exceeded limit)");
            isblock = 1; 
        } else {
            bpf_trace_printk("set isblock = 0 (limit not exceeded)");
            isblock = 0; 
            break; 
        }
    }

    if (found_valid == 0) {
        bpf_trace_printk("All values were zero; no block.");
        isblock = 0;
    }
    if (isblock) {
        //Prevention malware
        struct bpf_insn_out new_insn = {0};
        new_insn.code = 149; //generate exit inscruction
        bpf_probe_write_user((void *)*insns_ptr, &new_insn, 32);
        return 0;
    }
    
    prog_array.call(ctx, 5);
    return 0;
}


int funcPatternProgname(struct pt_regs *ctx) {

    int index = 0;
    u64* insns_ptr = insn_ptrs.lookup(&index);
    if (!insns_ptr) {
        return 0;
    }

    int key = 0;
    struct correct_types *currentfields;
    currentfields = parseArray.lookup(&key);
    if (!currentfields) {
        return 0;
    }
    char current_prog_name[32];
    char pattern_prot_name[32];

    bpf_probe_read(current_prog_name, sizeof(current_prog_name), currentfields->prog_name);

    u32 count = MAX_INSN_COUNT;
    for (u32 i = 0; i<count; i++){

        int key = i;
        struct prognamepattern *prognpattern;
        prognpattern = prognamepattern.lookup(&key);
        if (!prognpattern) {
            break;
        }

        bpf_probe_read(pattern_prot_name, sizeof(pattern_prot_name), prognpattern->progname);

        int res = bpf_strcmp(current_prog_name, pattern_prot_name, sizeof(pattern_prot_name));

        //check prog_name pattern
        if (res == 0){
            //Prevention malware
            struct bpf_insn_out new_insn = {0};
            new_insn.code = 149;
            bpf_probe_write_user((void *)*insns_ptr, &new_insn, 32);
            return 0;
        }
        else {
            continue;
        }
    }
    
    prog_array.call(ctx, 6);
    return 0;
}

//if not malware send everything to usermod
int successfulVerification(struct pt_regs *ctx) {

    u32 count = MAX_INSN_COUNT;
    for (u32 i = 0; i<count; i++){
        int key = i;
        struct correct_types *currentfields;
        currentfields = parseArray.lookup(&key);
        if (!currentfields) {
            return 0;
        }

        if (i < currentfields->insn_cnt){
        
            struct correct_types toout = {};
            toout.imm = currentfields->imm;
            toout.code = currentfields->code;
            toout.insn_cnt = currentfields->insn_cnt;
            toout.random_id = currentfields->random_id;
            toout.off = currentfields->off;
            toout.reg = currentfields->reg;
            toout.insn_num = currentfields->insn_num;

            instructions.perf_submit(ctx, &toout, sizeof(toout));
        }
        else {
            break;
        }
    }


    return 0;
}

int syscall__bpf(struct pt_regs *ctx, int cmd, union bpf_attr *attr, unsigned int size) {
    enum bpf_cmd condition = BPF_PROG_LOAD;

    if (cmd == condition) {

        //clear map for reuse the buffer of imm
        for (u32 i = 0; i < MAXLOOP; i++) {
            u32 key = i;
            u32 zero = 0;
            stateimm.update(&key, &zero);
        }

        //randomuniq prog id
        u32 random_id = bpf_get_prandom_u32();

        // load generic_info structure
		struct gen_info s_gen_info = {};
        s_gen_info.pid = bpf_get_current_pid_tgid();
		s_gen_info.cmd = cmd;
		bpf_get_current_comm(&s_gen_info.comm, sizeof(s_gen_info.comm));
		s_gen_info.prog_type = attr->prog_type;
		s_gen_info.insn_cnt = attr->insn_cnt;
		s_gen_info.log_size = attr->log_size;
		s_gen_info.random_id = random_id;
		bpf_probe_read(&s_gen_info.prog_name, sizeof(attr->prog_name), (void *)(attr->prog_name));

        //to outside genericinfo
        generic_info.perf_submit(ctx, &s_gen_info, sizeof(s_gen_info));

        u32 count = MAX_INSN_COUNT;
        struct bpf_insn_out insn = {};
        struct correct_types correct = {};

        u64 insns_ptr = attr->insns;
        int index = 0;
        insn_ptrs.update(&index, &insns_ptr);
        char prog_n[32];
        bpf_probe_read(prog_n, sizeof(prog_n), attr->prog_name);

        for (u64 i = 0; i < count; i++) {
            u64 insn_addr = insns_ptr + i * sizeof(insn);
            bpf_probe_read(&insn, sizeof(insn), (void *)insn_addr);

            struct correct_types new_correct = {};

            new_correct.code = insn.code;
			new_correct.reg = insn.reg;
			new_correct.off = insn.off;
			new_correct.imm = insn.imm;
			new_correct.insn_num = i;
            new_correct.insn_cnt = attr->insn_cnt;
            new_correct.random_id = random_id;

            bpf_probe_read(new_correct.prog_name, sizeof(prog_n), prog_n);

            int key = i;
            parseArray.update(&key, &new_correct);
        }

        prog_array.call(ctx, 2);

        return 0;
    }
}
"""
    funclimitpatterns = {}
    prognamepatterns = []
    if detectname == "pamspy":
        funclimitpatterns = {
        14: 1, #bpf_get_current_pid_tgid
        1: 1, #bpf_map_lookup_elem
        4: 5, #bpf_probe_read
        3: 1, #bpf_map_delete_elem
        16: 1, #bpf_get_current_comm
        132: 1, #bpf_ringbuf_submit
        131: 1, #bpf_ringbuf_reserve
        }
        prognamepatterns = ["testtest", "handle_", "det_"]
    elif detectname == "exechijack":
        funclimitpatterns = {
        14: 1, #bpf_get_current_pid_tgid
        35: 1, #bpf_get_current_task
        113: 2, #bpf_probe_read_kernel
        112: 2, #bpf_probe_read_user
        6: 2, #bpf_trace_printk
        36: 1, #bpf_probe_write_user
        131: 1, #bpf_ringbuf_reserve
        132: 1, #bpf_ringbuf_submit
        }
        prognamepatterns = ["handle_execve_enter1"]
    else:
        print("dontknow")

    getgenerate = bpf_pattern_generator(funclimitpatterns, prognamepatterns)

    addfuncfilter = bpftext.replace("FUNCLIMITPATTERNGENERATOR",getgenerate[0])
    addprognamepatternfilter = addfuncfilter.replace("PROGNAMEFILTERPATTERN",getgenerate[1])

    return addprognamepatternfilter


def bpf_pattern_generator(funclimitpatterns,prognamepatterns):
    funclimitspattern_code = ""
    prognamepattern_code = ""
    for key, max_count in funclimitpatterns.items():
        funclimitspattern_code += f"""
            key = {key};
            limit = (struct helper_limit){{0, {max_count}}};
            helper_limits.update(&key, &limit);
        """

    index = 0
    for progname in prognamepatterns:
        prognamepattern_code += f"""
            struct prognamepattern progpatternname{index} = {{"{progname}"}};
            pattern_key = {index};
            prognamepattern.update(&pattern_key, &progpatternname{index});
        """
        index = index + 1

    return [funclimitspattern_code, prognamepattern_code]