// catline_shell.cpp — CatLine Security Shell (Nmap Edition)
// Terminal especializado em Red Team / Auditoria de Rede
// Inspiração e suporte: pfdinc

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <vector>
#include <map>

#define TOKENSIZE   128
#define LOG_FILE    "log.txt"
#define ANALYZER    "python3 analyzer.py"
#define NMAP_OUTDIR "nmap_results"

// ── Cores ANSI ────────────────────────────────────────────────────────────────
#define RST   "\033[0m"
#define RED   "\033[1;31m"
#define GRN   "\033[1;32m"
#define YEL   "\033[1;33m"
#define BLU   "\033[1;34m"
#define CYN   "\033[1;36m"
#define MAG   "\033[1;35m"
#define WHT   "\033[1;37m"
#define DIM   "\033[2m"
#define BOLD  "\033[1m"

using namespace std;

// ── Protótipos ────────────────────────────────────────────────────────────────
void   StrTokenizer(char *input, char **argv);
void   myExecvp(char **argv);
int    RunAnalyzer(const char *input);
void   LogCommand(const char *input, const char *level);
void   PrintBanner();
bool   HandleBuiltins(const char *input);
bool   HandleNmapShortcuts(const string &input);
void   EnsureNmapDir();
string GetTimestamp();
string SanitizeArg(const string &s);
void   PrintNmapManual();
void   RunNmap(const string &nmapCmd, const string &ip, const string &tag);

// ── Timestamp ────────────────────────────────────────────────────────────────
string GetTimestamp()
{
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

// ── Sanitização básica contra injeção de shell ───────────────────────────────
// Remove caracteres perigosos antes de compor comandos com system()
string SanitizeArg(const string &s)
{
    string out;
    out.reserve(s.size());
    for (char c : s) {
        // Permite apenas IPv4/IPv6, hostnames, traços e pontos
        if (isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_' || c == ':')
            out += c;
    }
    return out;
}

// ── Log ──────────────────────────────────────────────────────────────────────
void LogCommand(const char *input, const char *level)
{
    ofstream logfile(LOG_FILE, ios::app);
    if (logfile.is_open()) {
        logfile << "[" << GetTimestamp() << "] [" << level << "] " << input << "\n";
        logfile.close();
    }
}

// ── Garante pasta de resultados nmap ────────────────────────────────────────
void EnsureNmapDir()
{
    // Usa execvp — sem system()
    struct stat st;
    if (stat(NMAP_OUTDIR, &st) != 0) {
        char *args[] = { (char*)"mkdir", (char*)"-p", (char*)NMAP_OUTDIR, NULL };
        pid_t pid = fork();
        if (pid == 0) { execvp("mkdir", args); exit(1); }
        else if (pid > 0) { int s; waitpid(pid, &s, 0); }
    }
}

// ── Executa nmap com saída dual (tela + arquivo) ────────────────────────────
void RunNmap(const string &nmapCmd, const string &ip, const string &tag)
{
    EnsureNmapDir();

    // Nome do arquivo: nmap_results/<ip>_<tag>_<timestamp>.txt
    string ts = GetTimestamp();
    for (char &c : ts) if (c == ' ' || c == ':') c = '-';

    string safeIp  = SanitizeArg(ip);
    string outFile = string(NMAP_OUTDIR) + "/" + safeIp + "_" + tag + "_" + ts + ".txt";
    string xmlFile = string(NMAP_OUTDIR) + "/" + safeIp + "_" + tag + "_" + ts + ".xml";

    // Monta: bash -c "nmap ... 2>&1 | tee <outfile>"
    // -oX para XML separado
    string fullCmd = nmapCmd + " -oX " + xmlFile + " 2>&1 | tee " + outFile;

    cout << CYN << "\n  [NMAP] Executando: " << RST << BOLD << fullCmd << RST << "\n";
    cout << DIM  << "  [NMAP] Salvando em: " << outFile << " e " << xmlFile << RST << "\n\n";

    // Usa bash -c para suportar pipe/tee
    char *args[] = { (char*)"bash", (char*)"-c", (char*)fullCmd.c_str(), NULL };
    pid_t pid = fork();
    if (pid == 0) {
        execvp("bash", args);
        cerr << RED << "\n  [CATLINE] Erro: bash nao encontrado.\n" << RST;
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        cout << GRN << "\n  [NMAP] Resultado salvo em " << outFile << RST << "\n\n";
        LogCommand(fullCmd.c_str(), "NMAP");
    }
}

// ── Atalhos Nmap ────────────────────────────────────────────────────────────
// Retorna true se o input foi um atalho nmap (não passa pelo analyzer)
bool HandleNmapShortcuts(const string &raw)
{
    // Tokeniza manualmente
    istringstream iss(raw);
    vector<string> tokens;
    string tok;
    while (iss >> tok) tokens.push_back(tok);
    if (tokens.empty()) return false;

    string cmd = tokens[0];
    string ip  = (tokens.size() >= 2) ? SanitizeArg(tokens[1]) : "";
    string extra = (tokens.size() >= 3) ? tokens[2] : "";

    // ── Tabela de atalhos ──────────────────────────────────────────────────
    // Cada atalho mapeia para: (flags nmap, tag do arquivo, nível de ruído)
    // Nível de ruído: 0=silencioso 1=normal 2=barulhento 3=muito barulhento
    struct NmapPreset {
        string flags;
        string tag;
        int    noise;   // 0-3
        string desc;
    };

    map<string, NmapPreset> presets = {
        // Reconhecimento rápido
        {"scan-fast",    {"nmap -F -T4",                        "fast",    2, "Scan rapido (-F -T4) — barulhento para IDS"}},
        {"scan-ping",    {"nmap -sn",                           "ping",    0, "Ping sweep — detecta hosts ativos"}},
        {"scan-top",     {"nmap --top-ports 100 -T3",           "top100",  1, "Top 100 portas — equilibrado"}},

        // Furtivo / evasao
        {"scan-stealth", {"nmap -sS -Pn -T2 -D RND:10",        "stealth", 0, "SYN scan furtivo com decoys — baixo ruido"}},
        {"scan-frag",    {"nmap -sS -f -Pn",                   "frag",    0, "Fragmentacao de pacotes — evade firewalls simples"}},
        {"scan-idle",    {"nmap -sI zombie " ,                  "idle",    0, "Idle scan via zombie (requer host zumbi)"}},
        {"scan-slow",    {"nmap -sS -T1 -Pn",                  "slow",    0, "Paranoid timing — quase indetectavel, muito lento"}},

        // Enumeracao
        {"scan-full",    {"nmap -sS -sV -p- -A -T4",           "full",    3, "Full scan — MUITO barulhento, detectavel por IDS"}},
        {"scan-version", {"nmap -sV --version-intensity 9",    "version", 2, "Deteccao de versao agressiva"}},
        {"scan-os",      {"nmap -O --osscan-guess",             "os",      2, "Fingerprinting de SO"}},
        {"scan-udp",     {"nmap -sU --top-ports 50 -T3",       "udp",     2, "Scan UDP top 50 portas"}},

        // Vulnerabilidades
        {"scan-vuln",    {"nmap --script vuln",                 "vuln",    3, "Scripts NSE de vulnerabilidade — MUITO barulhento"}},
        {"scan-http",    {"nmap -p 80,443,8080,8443 --script http-enum,http-title,http-headers", "http", 2, "Enumeracao HTTP/HTTPS"}},
        {"scan-smb",     {"nmap -p 445 --script smb-vuln-*,smb-enum-*", "smb",  3, "Auditoria SMB — detectavel"}},
        {"scan-ssh",     {"nmap -p 22 --script ssh-auth-methods,ssh-hostkey", "ssh", 1, "Auditoria SSH"}},
        {"scan-dns",     {"nmap -p 53 --script dns-brute,dns-zone-transfer", "dns", 2, "Enumeracao DNS"}},
        {"scan-ftp",     {"nmap -p 21 --script ftp-anon,ftp-bounce,ftp-vuln*", "ftp", 2, "Auditoria FTP"}},
        {"scan-db",      {"nmap -p 3306,5432,1433,1521,6379,27017 --script *-databases*", "db", 2, "Scan de bancos de dados"}},

        // Firewall / evasao avancada
        {"scan-fw",      {"nmap -sA -Pn",                      "fw",      1, "ACK scan para mapear firewall"}},
        {"scan-mtu",     {"nmap --mtu 24 -sS -Pn",             "mtu",     0, "MTU customizado — evasao de DPI"}},
        {"scan-source",  {"nmap --source-port 53 -sS -Pn",     "sport53", 0, "Source port 53 — evasao de firewall"}},
    };

    auto it = presets.find(cmd);
    if (it == presets.end()) return false;

    const NmapPreset &p = it->second;

    // Aviso de ruído ANTES de executar
    if (p.noise >= 3) {
        cout << RED << BOLD << "\n  [NMAP] ALERTA: " << RST
             << RED << p.desc << RST << "\n";
        cout << RED << "  Este scan e MUITO BARULHENTO e sera detectado por IDS/IPS/SIEM.\n" << RST;
        cout << YEL << "  Digite 'CONFIRMO' para prosseguir: " << RST;
        string conf; getline(cin, conf);
        if (conf != "CONFIRMO") {
            cout << "  [CATLINE] Scan cancelado.\n\n";
            LogCommand(raw.c_str(), "CANCELLED");
            return true;
        }
    } else if (p.noise == 2) {
        cout << YEL << "\n  [NMAP] AVISO: " << RST << p.desc << "\n";
        cout << YEL << "  Pode ser detectado por IDS. Continuar? [s/N]: " << RST;
        string conf; getline(cin, conf);
        if (conf != "s" && conf != "S") {
            cout << "  [CATLINE] Scan cancelado.\n\n";
            LogCommand(raw.c_str(), "CANCELLED");
            return true;
        }
    } else if (p.noise <= 1) {
        cout << GRN << "\n  [NMAP] " << p.desc << RST << "\n";
    }

    if (ip.empty()) {
        cout << YEL << "  Uso: " << cmd << " <ip/host>" << RST << "\n\n";
        return true;
    }

    string fullFlags = p.flags + " " + ip;
    if (!extra.empty()) fullFlags += " " + extra;

    RunNmap(fullFlags, ip, p.tag);
    return true;
}

// ── Manual interativo de Nmap ────────────────────────────────────────────────
void PrintNmapManual()
{
    cout << "\n" << CYN << BOLD
         << "  ╔══════════════════════════════════════════════════════╗\n"
         << "  ║         CATLINE — MANUAL NMAP (Red Team Edition)    ║\n"
         << "  ╚══════════════════════════════════════════════════════╝\n"
         << RST << "\n";

    auto section = [](const char *t) {
        cout << MAG << BOLD << "  ── " << t << " ──\n" << RST;
    };
    auto entry = [](const char *cmd, int noise, const char *desc) {
        const char *bar = (noise==0)?"\033[1;32m●\033[0m"
                         :(noise==1)?"\033[1;33m●\033[0m"
                         :(noise==2)?"\033[1;31m●\033[0m"
                                    :"\033[5;31m●\033[0m";
        printf("  %-26s %s  %s\n", cmd, bar, desc);
    };

    cout << DIM << "  Ruído: " RST GRN "● Silencioso  " RST YEL "● Normal  " RST RED "● Barulhento  " RST "\033[5;31m● CRÍTICO\n\n" RST;

    section("RECONHECIMENTO");
    entry("scan-ping  <ip>",    0, "Ping sweep — descobre hosts vivos");
    entry("scan-fast  <ip>",    2, "100 portas mais comuns, rapido");
    entry("scan-top   <ip>",    1, "Top 100 portas, timing T3");

    section("FURTIVO / EVASAO");
    entry("scan-stealth <ip>",  0, "SYN furtivo com decoys (-D RND:10)");
    entry("scan-slow  <ip>",    0, "T1 paranoid — quase indetectavel");
    entry("scan-frag  <ip>",    0, "Fragmentacao — evade firewalls simples");
    entry("scan-mtu   <ip>",    0, "MTU 24 — evasao de DPI");
    entry("scan-source <ip>",   0, "Source port 53 — evasao de regra");
    entry("scan-idle  zombie <ip>", 0, "Idle scan via host zumbi");

    section("ENUMERACAO COMPLETA");
    entry("scan-full  <ip>",    3, "ALL ports + versao + OS — CRITICO");
    entry("scan-version <ip>",  2, "Deteccao de versao intensa");
    entry("scan-os    <ip>",    2, "Fingerprint de sistema operacional");
    entry("scan-udp   <ip>",    2, "UDP top 50 portas");
    entry("scan-fw    <ip>",    1, "ACK scan — mapeia regras de firewall");

    section("SERVICOS ESPECIFICOS");
    entry("scan-http  <ip>",    2, "HTTP/HTTPS enum + headers");
    entry("scan-smb   <ip>",    3, "SMB vulnerabilidades — CRITICO");
    entry("scan-ssh   <ip>",    1, "Auth methods + hostkey SSH");
    entry("scan-dns   <ip>",    2, "Brute DNS + zone transfer");
    entry("scan-ftp   <ip>",    2, "FTP anon + bounce + vulns");
    entry("scan-db    <ip>",    2, "Bancos: MySQL/Postgres/MSSQL/Redis/Mongo");

    section("VULNERABILIDADES");
    entry("scan-vuln  <ip>",    3, "NSE vuln scripts — CRITICO p/ IDS");

    cout << "\n" DIM "  Resultados salvos em: " RST BOLD "./" NMAP_OUTDIR "/<ip>_<tipo>_<hora>.txt + .xml\n" RST;
    cout << DIM  "  Flags diretas tambem funcionam: " RST "nmap -sS -p 80 192.168.1.1\n\n";
}

// ── Banner ───────────────────────────────────────────────────────────────────
void PrintBanner()
{
    cout << "\n" RED BOLD
         << "  ██████╗ █████╗ ████████╗██╗     ██╗███╗   ██╗███████╗\n"
         << " ██╔════╝██╔══██╗╚══██╔══╝██║     ██║████╗  ██║██╔════╝\n"
         << " ██║     ███████║   ██║   ██║     ██║██╔██╗ ██║█████╗  \n"
         << " ██║     ██╔══██║   ██║   ██║     ██║██║╚██╗██║██╔══╝  \n"
         << " ╚██████╗██║  ██║   ██║   ███████╗██║██║ ╚████║███████╗\n"
         << "  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝\n"
         << RST;
    cout << MAG BOLD
         << "\n  [ CatLine Security Shell — Nmap Red Team Edition ]\n"
         << RST DIM
         << "  [ Log: " LOG_FILE " | Results: " NMAP_OUTDIR "/ | Analyzer: Python AI ]\n"
         << RST "\n"
         << WHT "  Digite " CYN "nmap-manual" WHT " para ver todos os atalhos de scan.\n"
         << WHT "  Digite " CYN "help" WHT " para ajuda geral. " CYN "exit" WHT " para sair.\n"
         << RST "\n"
         << DIM "  ─────────────────────────────────────────────────────\n\n" RST;
}

// ── Analisador Python ────────────────────────────────────────────────────────
int RunAnalyzer(const char *input)
{
    // Escapa aspas simples para não quebrar o shell
    string escaped(input);
    size_t pos = 0;
    while ((pos = escaped.find("'", pos)) != string::npos) {
        escaped.replace(pos, 1, "'\\''");
        pos += 4;
    }
    string cmd = string(ANALYZER) + " '" + escaped + "'";
    int ret = system(cmd.c_str());
    if (ret == -1) return 0;
    return WEXITSTATUS(ret);
}

// ── Fork/execvp ─────────────────────────────────────────────────────────────
void myExecvp(char **argv)
{
    pid_t pid = fork();
    if (pid == 0) {
        if (execvp(*argv, argv) < 0)
            cerr << RED "\n  [CATLINE] Comando nao encontrado: " << *argv << "\n" RST;
        exit(1);
    } else if (pid < 0) {
        cerr << RED "\n  [CATLINE] Erro: fork() falhou.\n" RST;
    } else {
        int status;
        waitpid(pid, &status, 0);
    }
}

// ── Tokenizador ─────────────────────────────────────────────────────────────
void StrTokenizer(char *input, char **argv)
{
    char *token = strtok(input, " ");
    while (token != NULL) {
        *argv++ = token;
        token   = strtok(NULL, " ");
    }
    *argv = NULL;
}

// ── Builtins ─────────────────────────────────────────────────────────────────
bool HandleBuiltins(const char *input)
{
    if (strcmp(input, "nmap-manual") == 0) {
        PrintNmapManual();
        return true;
    }
    if (strcmp(input, "help") == 0) {
        cout << "\n" CYN BOLD "  CatLine Security Shell — Red Team Edition\n" RST
             << DIM "  ─────────────────────────────────────────────────────\n" RST
             << "\n"
             << WHT "  Comandos especiais:\n" RST
             << "    " CYN "nmap-manual" RST "  → manual completo de atalhos nmap\n"
             << "    " CYN "logview" RST "      → historico de comandos\n"
             << "    " CYN "results" RST "      → listar resultados de scans salvos\n"
             << "    " CYN "help" RST "         → esta ajuda\n"
             << "    " CYN "exit" RST "         → sair\n"
             << "\n"
             << WHT "  Niveis de risco da IA:\n" RST
             << "    " GRN "[OK]   " RST "SAFE    → executa direto\n"
             << "    " YEL "[!]    " RST "WARNING → pede confirmacao [s/N]\n"
             << "    " RED "[!!]   " RST "DANGER  → exige digitar CONFIRMO\n"
             << "    " RED "[BLOQ] " RST "BLOCK   → bloqueado definitivamente\n\n";
        return true;
    }
    if (strcmp(input, "logview") == 0) {
        cout << "\n" CYN "  ─── Historico de comandos ───\n\n" RST;
        char *args[] = { (char*)"cat", (char*)LOG_FILE, NULL };
        pid_t pid = fork();
        if (pid == 0) { execvp("cat", args); exit(1); }
        else if (pid > 0) { waitpid(pid, nullptr, 0); }
        cout << "\n";
        return true;
    }
    if (strcmp(input, "results") == 0) {
        cout << "\n" CYN "  ─── Scans salvos em " NMAP_OUTDIR "/ ───\n\n" RST;
        char *args[] = { (char*)"ls", (char*)"-lh", (char*)"--color=auto", (char*)NMAP_OUTDIR, NULL };
        pid_t pid = fork();
        if (pid == 0) { execvp("ls", args); exit(1); }
        else if (pid > 0) { waitpid(pid, nullptr, 0); }
        cout << "\n";
        return true;
    }
    return false;
}

// ── Main ─────────────────────────────────────────────────────────────────────
int main()
{
    char  input[512];       // buffer maior para suportar comandos longos
    char  inputCopy[512];
    char *argv[TOKENSIZE];

    PrintBanner();
    EnsureNmapDir();
    LogCommand("=== SESSAO INICIADA ===", "INFO");

    while (true)
    {
        // Prompt: [CATLINE-SH] (Nmap-Active) ->
        cout << "\n" RED "[" RST GRN "CATLINE-SH" RST RED "]" RST
             << CYN " (Nmap-Active)" RST " " BLU "->" RST " ";
        cout.flush();

        if (!cin.getline(input, sizeof(input))) break;
        if (strlen(input) == 0) continue;

        // Exit
        if (strcmp(input, "exit") == 0) {
            LogCommand("=== SESSAO ENCERRADA ===", "INFO");
            cout << "\n  " GRN "[CATLINE]" RST " Encerrando sessao. Stay safe.\n\n";
            break;
        }

        // Builtins (help, logview, results, nmap-manual)
        if (HandleBuiltins(input)) continue;

        // Atalhos Nmap — intercepta ANTES do analyzer
        if (HandleNmapShortcuts(string(input))) continue;

        // Análise de segurança via Python IA
        strncpy(inputCopy, input, sizeof(inputCopy) - 1);
        inputCopy[sizeof(inputCopy) - 1] = '\0';

        int riskLevel = RunAnalyzer(inputCopy);

        if (riskLevel == 3) {
            LogCommand(input, "BLOCKED");
            cout << "\n  " RED "[CATLINE]" RST " Comando BLOQUEADO pela IA.\n\n";
            continue;
        }
        if (riskLevel == 2) {
            LogCommand(input, "DANGER");
            cout << "  " RED "[CATLINE]" RST " PERIGO! Digite 'CONFIRMO' para continuar: ";
            string conf; getline(cin, conf);
            if (conf != "CONFIRMO") {
                cout << "  [CATLINE] Cancelado.\n\n";
                continue;
            }
        }
        else if (riskLevel == 1) {
            LogCommand(input, "WARNING");
            cout << "  " YEL "[CATLINE]" RST " Continuar? [s/N]: ";
            string conf; getline(cin, conf);
            if (conf != "s" && conf != "S") {
                cout << "  [CATLINE] Cancelado.\n\n";
                continue;
            }
        }
        else {
            LogCommand(input, "SAFE");
        }

        // Executa o comando
        char execBuf[512];
        strncpy(execBuf, input, sizeof(execBuf) - 1);
        execBuf[sizeof(execBuf) - 1] = '\0';

        StrTokenizer(execBuf, argv);
        if (argv[0] != NULL) {
            cout << "\n";
            myExecvp(argv);
        }
    }

    return 0;
}
