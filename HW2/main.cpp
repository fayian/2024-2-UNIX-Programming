#include <string>
#include <sstream>
#include <vector>

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

using std::ostringstream;
using std::string;
using std::vector;

class Sdb {
private:    
    string m_load_path;
    string m_load_filename;
    csh m_capstone_handle;
    pid_t m_trace_pid;

    bool is_valid_address(uint64_t address) {
        FILE* maps = fopen(("/proc/" + std::to_string(m_trace_pid) + "/maps").c_str(), "r");
        if (!maps) {
            perror("[ERROR][is_valid_rip] fopen");
            return false;
        }

        uint64_t start_addr;
        uint64_t end_addr;
        char line[256];

        while (fgets(line, sizeof(line), maps)) {
            // Check if the line contains the binary path
            if (strstr(line, m_load_filename.c_str())) {
                sscanf(line, "%lx-%lx", &start_addr, &end_addr);
                if(start_addr <= address && address < end_addr) {
                    fclose(maps);
                    return true;
                }
                if(address == end_addr) {
                    fclose(maps);
                    return false;
                }
            }
        }

        fclose(maps);
        return false;
    }

    // returns disassembled instruction count
    int disassemble(int instruction_count = 5, uint64_t rip = 0) {
        cs_insn* instruction;
        user_regs_struct regs;

        // Get RIP
        if(rip == 0) {
            if(ptrace(PTRACE_GETREGS, m_trace_pid, 0, &regs)) {
                perror("[ERROR][disassemble] PTRACE_GETREGS");
                return -1;
            };
            rip = regs.rip;
        }

        for(int i = 0; i < instruction_count; i++) {
            if(!is_valid_address(rip)) {
                printf("** the address is out of the range of the executable region.\n");
                return i;
            }
            
            // Fetch instuction memory
            uint8_t code[16];
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, m_trace_pid, rip, NULL);
            if(errno != 0) {
                perror("[ERROR][dissasemble] PTRACE_PEEKTEXT");
                return -1;
            }
            memcpy(code, &data, sizeof(data));

            data = ptrace(PTRACE_PEEKDATA, m_trace_pid, rip + 8, NULL);
            if(errno != 0) {
                perror("[ERROR][dissasemble] PTRACE_PEEKTEXT");
                return -1;
            }
            memcpy(code + 8, &data, sizeof(data));
            

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

    uint64_t get_entry_point(const string& elf_file_path) {
        FILE* file = fopen(("/proc/" + std::to_string(m_trace_pid) + "/auxv").c_str(), "rb");
        if (!file) {
            perror("[ERROR][get_entry_point] fopen");
            return -1;
        }
    
        Elf64_auxv_t aux;
        while (fread(&aux, sizeof(aux), 1, file) == 1) {
            if(aux.a_type == AT_ENTRY) {
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
            uint64_t entry_point = get_entry_point(load_path);
            if(entry_point == uint64_t(-1)) return -1;
            printf("** program \'%s\' loaded. entry point: %lx.\n", 
                load_path.c_str(), entry_point);

            // Disassemble
            disassemble(5, entry_point);
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