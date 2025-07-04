#include <string>
#include <sstream>
#include <vector>

#include <endian.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <capstone/capstone.h>

using std::istringstream;
using std::ostringstream;
using std::string;
using std::vector;

class Sdb {
private:    
    string m_load_path;
    string m_load_filename;
    csh m_capstone_handle;
    pid_t m_trace_pid;
    vector<uint64_t> m_breakpoints;
    vector<uint8_t> m_original_byte;

    // return -1 if not, else breakpoint index 
    int check_breakpoint(uint64_t address) {
        if(address == 0) return -1;
        for(size_t i = 0; i < m_breakpoints.size(); i++) {
            if(m_breakpoints[i] == address) return i;
        }
        return -1;
    }

    bool is_valid_address(uint64_t address) {
        FILE* maps = fopen(("/proc/" + std::to_string(m_trace_pid) + "/maps").c_str(), "r");
        if (!maps) {
            perror("[ERROR][is_valid_rip] fopen");
            return false;
        }

        uint64_t start_addr;
        uint64_t end_addr;
        char line[256];
        char permission[5];

        while (fgets(line, sizeof(line), maps)) {
            // Check if the line contains the binary path
            if (strstr(line, m_load_filename.c_str())) {
                sscanf(line, "%lx-%lx %s ", &start_addr, &end_addr, permission);
                if(start_addr <= address && address < end_addr && permission[2] == 'x') {
                    fclose(maps);
                    return true;
                }
            }
        }

        fclose(maps);
        return false;
    }

    uint64_t get_rip() {
        user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, m_trace_pid, 0, &regs)) {
            perror("[ERROR][get_rip] PTRACE_GETREGS");
            return -1;
        };
        return regs.rip;
    }

    long get_memory(uint64_t address) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, m_trace_pid, address, NULL);
        if(errno != 0) {
            if(errno == EFAULT || errno == EIO) 
                printf("** the target address is not valid.\n");
            else
                perror("[ERROR][get_memory] PTRACE_PEEKTEXT\n");
            return -1;
        }
        return data;
    }

    int set_memory(uint64_t address, uint8_t data[8]) {
        uint64_t data_;
        memcpy(&data_, data, sizeof(data_));
        if(ptrace(PTRACE_POKETEXT, m_trace_pid, address, data_) < 0) {
            if(errno == EFAULT || errno == EIO) 
                printf("** the target address is not valid.\n");
            else
                perror("[ERROR][set_memory] PTRACE_POKETEXT\n");
            return -1;
        }
        return 0;
    }

    //returns the original bit
    uint8_t set_interrupt(uint64_t address) {
        uint8_t mem[8];

        long data = get_memory(address);
        memcpy(mem, &data, sizeof(data));

        uint8_t original = mem[0];
        mem[0] = 0xCC;
        set_memory(address, mem);

        return original;
    }

    void restore_interrupt(uint64_t address, uint8_t original_byte) {
        uint8_t mem[8];

        long data = get_memory(address);
        memcpy(mem, &data, sizeof(data));

        mem[0] = original_byte;
        set_memory(address, mem);
    }

    void revert_rip() {
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, m_trace_pid, 0, &regs) < 0) {
            perror("[ERROR][restore_interrupt] PTRACE_GETREGS");
            return;
        }
        regs.rip -= 1;
        if (ptrace(PTRACE_SETREGS, m_trace_pid, 0, &regs) < 0) {
            perror("[ERROR][restore_interrupt] PTRACE_SETREGS");
        }
    }

    // returns disassembled instruction count
    int disassemble(uint64_t rip, int instruction_count = 5) {
        cs_insn* instruction;

        for(int i = 0; i < instruction_count; i++) {
            if(!is_valid_address(rip)) {
                printf("%lx\n", rip);
                printf("** the address is out of the range of the executable region.\n");
                return i;
            }
            
            // Fetch instuction memory
            uint8_t code[16];
            long data = get_memory(rip);
            memcpy(code, &data, sizeof(data));
            data = get_memory(rip + 8);
            memcpy(code + 8, &data, sizeof(data));

            // Check for breakpoints to restore
            for(int i = 0; i < 16; i++) {
                if(code[i] != 0xCC) continue;
                for(size_t j = 0; j < m_breakpoints.size(); j++) {
                    if(rip + i == m_breakpoints[j]) 
                        code[i] = m_original_byte[j];
                }
            }
            
            size_t count = cs_disasm(
                m_capstone_handle, 
                code,
                sizeof(code),
                rip,
                1,
                &instruction
            );

            if(count <= 0) {
                printf("[ERROR][dissasemble] cs_disasm: Failed\n");
                return -1;
            }

            printf("%lx:", instruction[0].address);
            for(int j = 0; j < instruction[0].size; j++) 
                printf(" %02x", instruction[0].bytes[j]);
            for(int j = 0; j < 15 - instruction[0].size; j++) 
                printf("   "); // padding

            printf("  %s\t\t%s\n", instruction[0].mnemonic, instruction[0].op_str);
            
            rip += instruction[0].size; // Increase RIP to fetch next instruction
            cs_free(instruction, count);
        }

        return instruction_count;
    }

    uint64_t get_entry_point(uint64_t type = AT_ENTRY) {
        FILE* file = fopen(("/proc/" + std::to_string(m_trace_pid) + "/auxv").c_str(), "rb");
        if (!file) {
            perror("[ERROR][get_entry_point] fopen");
            return -1;
        }
    
        Elf64_auxv_t aux;
        while (fread(&aux, sizeof(aux), 1, file) == 1) {
            if(aux.a_type == type) {
                fclose(file);
                return aux.a_un.a_val;
            }
        }
        fclose(file);
        return -1;
    }

    vector<string> process_input(char input[]) {
        vector<string> result;
        ostringstream token;
        int index = 0;
        char c;

        while((c = input[index]) != '\0') {
            if(c == '\r' || c == '\n') {
                result.push_back(token.str());
                return result;
            }

            if(c == ' ' || c == '\t') {
                while(c == ' ' || c == '\t') c = input[++index];
                if(token.str() != "") result.push_back(token.str());
                token.str("");
                token.clear();
            } else {
                token << c;
                index++;
            }
        }

        return result;
    }
   
    int si(bool print_disasm = true) {
        //Check if start on breakpoint
        uint64_t rip = get_rip();
        int breakpoint = check_breakpoint(rip);
        if(breakpoint != -1) {
            restore_interrupt(rip, m_original_byte[breakpoint]);
        }

        // Step
        if(ptrace(PTRACE_SINGLESTEP, m_trace_pid, 0, 0) < 0) {
            perror("[ERROR][si] PTRACE_SINGLESTEP");
            return -1;
        }        

        int status;
        if(waitpid(m_trace_pid, &status, 0) < 0) {
            perror("[ERROR][si] waitpid");
            return -1;
        }
        
        if(!WIFSTOPPED(status)) {
            printf("** the target program terminated.\n");
            return 1;
        }

        // Restore breakpoint
        if(breakpoint != -1) {
            set_interrupt(rip);
        }

        // Check if hit breakpoint
        rip = get_rip();
        if(check_breakpoint(rip) != -1) {
            printf("** hit a breakpoint at 0x%lx.\n", rip);
        }

        if(print_disasm)
            disassemble(rip);

        return 0;
    }
    int cont() {
        // One step to avoid start on breakpoint
        si(false);

        if(ptrace(PTRACE_CONT, m_trace_pid, 0, 0) < 0) {
            perror("[ERROR][cont] PTRACE_CONT");
            return -1;
        }        

        int status;
        if(waitpid(m_trace_pid, &status, 0) < 0) {
            perror("[ERROR][cont] waitpid");
            return -1;
        }        
        
        if(!WIFSTOPPED(status)) {
            printf("** the target program terminated.\n");
            return 1;
        }

        revert_rip();
        uint64_t rip = get_rip();
        printf("** hit a breakpoint at 0x%lx.\n", rip);
        
        disassemble(rip);
        return 0;
    }
    int info_reg() {
        user_regs_struct regs;
        
        if(ptrace(PTRACE_GETREGS, m_trace_pid, 0, &regs)) {
            perror("[ERROR][info_reg] PTRACE_GETREGS");
            return -1;
        };
        printf("$rax 0x%016llx\t$rbx 0x%016llx\t$rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
        printf("$rdx 0x%016llx\t$rsi 0x%016llx\t$rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
        printf("$rbp 0x%016llx\t$rsp 0x%016llx\t$r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
        printf("$r9  0x%016llx\t$r10 0x%016llx\t$r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
        printf("$r12 0x%016llx\t$r13 0x%016llx\t$r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
        printf("$r15 0x%016llx\t$rip 0x%016llx\t$eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
        return 0;
    }
    int breakpoint(uint64_t address) {
        if(!is_valid_address(address)) {
            printf("** the target address is not valid.\n");
            return -1;
        }
        m_breakpoints.push_back(address);
        m_original_byte.push_back(set_interrupt(address));
        printf("** set a breakpoint at 0x%lx.\n", address);
        return 0;
    }
    int breakrva(uint64_t offset) {
        uint64_t entry = get_entry_point(AT_BASE);
        if(entry == 0) entry = 0x400000;
        return breakpoint(offset + entry);
    }
    void info_break() {
        bool have_breakpoint = false;
        for(size_t i = 0; i < m_breakpoints.size(); i++) {
            if(m_breakpoints[i] != 0)
                have_breakpoint = true;
        }

        if(!have_breakpoint) {
            printf("** no breakpoints.\n");
            return;
        }

        printf("Num\tAddress\n");

        for(size_t i = 0; i < m_breakpoints.size(); i++) {
            if(m_breakpoints[i] != 0) {
                printf("%ld\t0x%lx\n", i, m_breakpoints[i]);
            }
        }
    }
    void delete_break(int id) {
        if(id >= int(m_breakpoints.size()) || m_breakpoints[id] == 0) {
            printf("** breakpoint %d does not exist.\n", id);
        } else {
            restore_interrupt(m_breakpoints[id], m_original_byte[id]);
            m_breakpoints[id] = 0;
            printf("** delete breakpoint %d.\n", id);
        }
    }
    int patch_memory(uint64_t address, const string& hex_data) {
        char word[17];
        long data;
        uint8_t mem_bytes[1024];        

        int offset = 0;
        if(hex_data[0] == '0' && hex_data[1] == 'x')
            offset = 2;
        istringstream input_stream(hex_data.substr(offset));
        
        //offset = pad hex_data to align word
        offset = (8 - ((hex_data.size() - offset) / 2 % 8)) % 8;

        // Setup patch first iteration
        data = get_memory(address - offset);
        if(data == -1) return -1; //Check if starting memory is valid
        memcpy(mem_bytes, &data, sizeof(data));

        input_stream.read(word, (8 - offset) * 2);
        data = be64toh(std::stoull(word, nullptr, 16));
        uint8_t tmp[8];
        memcpy(tmp, &data, sizeof(data));
        for(int i = offset; i < 8; i++) {
            mem_bytes[i] = tmp[i];
        }

        int word_count = 1;

        // Setup patch        
        while(true) {            
            input_stream.read(word, 16); word[17] = '\0';
            if(input_stream.gcount() != 16) break;

            data = be64toh(std::stoull(word, nullptr, 16));
            memcpy(mem_bytes + word_count * 8, &data, sizeof(data));            

            ++word_count;
        }

        // Check ending memory
        if(get_memory(address - offset + 8 * word_count) == -1)
            return -1;

        // Write patch to memory
        for(int i = 0; i < word_count; i++) {
            if(set_memory(address - offset + 8 * i, mem_bytes + 8 * i) == -1)
                return -1;
        }

        // Reset breakpoints
        for(size_t i = 0; i < m_breakpoints.size(); i++) {
            if(address <= m_breakpoints[i] && m_breakpoints[i] < address + 8 * word_count) {
                m_original_byte[i] = set_interrupt(address);
            }
        }
        printf("** patch memory at 0x%lx.\n", address);
        return 0;
    }

public:
    Sdb() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone_handle) != CS_ERR_OK) {
            printf("[Error][Sdb] Failed to initialize Capstone\n");
            exit(1);
        }
    }
    ~Sdb() {
        cs_close(&m_capstone_handle);
    }

    int load(const string& load_path) {
        pid_t pid = fork();
        if(pid < 0) {
            perror("[ERROR][load] fork");
            return -1;
        }

        if(pid == 0) {
            //child
            if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
                perror("[ERROR][load] ptrace");
                exit(0);
            }
            
            if(execl(load_path.c_str(), load_path.c_str(), NULL) < 0) {
                perror("[ERROR][load] execl");
                fprintf(stderr, "%s\n", load_path.c_str());
                exit(0);
            }
        } else {
            //parent
            int status;
            if(waitpid(pid, &status, 0) < 0) {
                perror("[ERROR][load] waitpid");
                return -1;
            }

            //The child didn't send stop signal as it should
            if(!WIFSTOPPED(status)) {
                fprintf(stderr, "[ERROR][load] WIFSTOPPED return false\n");
                return -1; 
            }

            // Set member pid
            m_trace_pid = pid;

            // Get filename from filepath
            size_t pos = -1, next_pos = load_path.find('/');
            while(next_pos != string::npos) {
                pos = next_pos;
                next_pos = load_path.find('/', pos + 1);
            }
            m_load_filename = load_path.substr(pos + 1);

            // Get entry point
            uint64_t entry_point = get_entry_point();
            if(entry_point == uint64_t(-1)) return -1;
            printf("** program \'%s\' loaded. entry point: %lx.\n", 
                load_path.c_str(), entry_point);

            // Run until entry point
            uint8_t original = set_interrupt(entry_point);
            if(ptrace(PTRACE_CONT, m_trace_pid, 0, 0) < 0) {
                perror("[ERROR][load] PTRACE_CONT");
                return -1;
            }
            if(waitpid(m_trace_pid, &status, 0) < 0) {
                perror("[ERROR][load] waitpid");
                return -1;
            }
            if(!WIFSTOPPED(status)) {
                fprintf(stderr, "[ERROR][load] Something went wrong when continue\n");
                return -1; 
            }
            restore_interrupt(entry_point, original);
            revert_rip();

            // Disassemble
            disassemble(entry_point);
        }

        m_load_path = load_path;
        return 0;
    }

    void run() {        
        printf("(sdb) ");

        char raw_input[1024];
        vector<string> input;
        while(fgets(raw_input, sizeof(raw_input), stdin)) {
            input = process_input(raw_input);

            if(input[0] == "load") {
                load(input[1]);
            } else if(m_load_path == "") {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            } else if(input[0] == "si") {
                if(si() == 1) break;
            } else if(input[0] == "cont") {
                if(cont() == 1) break;
            } else if(input[0] == "info") {
                if(input[1] == "reg") {
                    info_reg();
                } else if(input[1] == "break") {
                    info_break();
                }
            } else if(input[0] == "break") {
                breakpoint(std::stoull(input[1], nullptr, 16));
            } else if(input[0] == "breakrva") {
                breakrva(std::stoull(input[1], nullptr, 16));
            } else if(input[0] == "delete") {
                delete_break(atoi(input[1].c_str()));
            } else if(input[0] == "patch") {
                patch_memory(std::stoull(input[1], nullptr, 16), input[2]);
            }

            printf("(sdb) ");
        }
    }
};

int main(int argc, char** argv) {    
    if(argc > 2) {
        fprintf(stderr, "Usage: ./sdb [program]\n");
        exit(1);
    }
    
    Sdb sdb;
    if(argc == 2) 
        sdb.load(argv[1]);

    sdb.run();

    return 0;
}