// ============================================================
// Mini Shell em C++
// Descrição: Um shell simples que lê comandos do usuário,
//            cria um processo filho e executa o comando.
// ============================================================

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;

// Número máximo de argumentos por comando
#define MAX_TOKENS 100

// Número máximo de caracteres por linha de comando
#define MAX_INPUT  250

// ============================================================
// Declarações das funções
// ============================================================

// Divide a linha de entrada em tokens (palavras separadas por espaço)
void tokenizar(char *input, char **argv);

// Cria um processo filho e executa o comando
void executar(char **argv);

// ============================================================
// Função principal
// ============================================================
int main()
{
    char input[MAX_INPUT];
    char *argv[MAX_TOKENS];

    while (true)
    {
        // Exibe o prompt do shell
        cout << "meu-shell> ";

        // Lê a linha digitada pelo usuário
        // cin.getline lê até MAX_INPUT-1 caracteres ou até encontrar '\n'
        if (!cin.getline(input, MAX_INPUT))
        {
            // Se chegou ao fim do arquivo (Ctrl+D), encerra o loop
            cout << "\nEncerrando o shell. Até logo!" << endl;
            break;
        }

        // Ignora linhas vazias
        if (strlen(input) == 0)
            continue;

        // Verifica se o usuário digitou "exit"
        if (strcmp(input, "exit") == 0)
        {
            cout << "Encerrando o shell. Até logo!" << endl;
            break;
        }

        // Divide o comando em tokens e executa
        tokenizar(input, argv);
        executar(argv);
    }

    return 0;
}

// ============================================================
// tokenizar: separa a string de entrada em palavras
//
// Parâmetros:
//   input  - a linha digitada pelo usuário (ex: "ls -la")
//   argv   - vetor onde serão guardados os ponteiros para cada palavra
//
// Funciona assim:
//   "ls -la /home"  →  argv[0]="ls", argv[1]="-la", argv[2]="/home", argv[3]=NULL
//
// O NULL no final é obrigatório para o execvp saber onde a lista termina.
// ============================================================
void tokenizar(char *input, char **argv)
{
    // strtok divide a string pelo delimitador (espaço)
    char *token = strtok(input, " ");

    while (token != NULL)
    {
        *argv++ = token;                  // Guarda o ponteiro para o token atual
        token   = strtok(NULL, " ");      // Avança para o próximo token
    }

    *argv = NULL; // Marca o fim da lista de argumentos (obrigatório para execvp)
}

// ============================================================
// executar: cria um processo filho e executa o comando
//
// Como funciona o fork():
//   - fork() duplica o processo atual
//   - No processo FILHO  : fork() retorna 0
//   - No processo PAI    : fork() retorna o PID do filho (número > 0)
//   - Se algo der errado : fork() retorna -1
// ============================================================
void executar(char **argv)
{
    // Verifica se o comando está vazio
    if (argv[0] == NULL)
        return;

    pid_t pid = fork(); // Cria o processo filho

    if (pid == 0)
    {
        // --- Estamos DENTRO do processo filho ---

        // execvp substitui o processo filho pelo programa solicitado.
        // Se funcionar, o código abaixo nunca é executado.
        // Se falhar (comando não encontrado), execvp retorna -1.
        if (execvp(argv[0], argv) == -1)
        {
            // Usamos perror para mostrar a mensagem de erro do sistema
            perror("Erro ao executar o comando");
        }

        // Encerra o processo filho mesmo em caso de erro
        exit(1);
    }
    else if (pid < 0)
    {
        // --- fork() falhou ---
        perror("Erro ao criar o processo filho");
    }
    else
    {
        // --- Estamos no processo PAI ---

        // O pai espera o filho terminar antes de mostrar o prompt novamente.
        // WUNTRACED: também retorna se o filho for pausado (ex: Ctrl+Z)
        int status;
        waitpid(pid, &status, WUNTRACED);
    }
}