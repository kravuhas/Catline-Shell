# 🔐 CatLine Security Shell — Nmap Red Team Edition

CatLine é um shell customizado em C++ com foco em segurança ofensiva (Red Team) e análise de risco em tempo real.

O projeto explora como um terminal pode evoluir além da simples execução de comandos, incorporando consciência de segurança, classificação de risco e suporte a auditoria de rede.

---

## 🚀 Visão Geral

Diferente de um shell tradicional, o CatLine:

* Analisa comandos antes da execução
* Classifica o nível de risco (SAFE / WARNING / DANGER / BLOCK)
* Detecta padrões suspeitos e possíveis abusos
* Integra atalhos inteligentes para Nmap
* Registra logs para auditoria

A proposta é simular um ambiente onde cada comando é tratado com contexto de segurança.

---

## 🧠 Filosofia do Projeto

Este projeto não é apenas sobre execução de comandos, mas sobre **consciência operacional**.

> “Um sistema que entende o impacto do que está sendo executado.”

---

## 📈 Evolução do Projeto

### 🔹 v1 — Mini Shell (implementação manual)

Primeira versão desenvolvida manualmente para compreender os fundamentos de sistemas Unix:

* Criação de processos com `fork()`
* Execução de programas com `execvp()`
* Parsing de comandos

Essa etapa foi essencial para construir a base técnica do projeto.

---

### 🔹 v2 — CatLine Security Shell

Evolução do projeto com foco em segurança e análise de risco:

* Classificação de comandos por nível de risco
* Integração com Nmap (atalhos inteligentes)
* Sistema de logging (txt + JSON)
* Análise de “ruído” de scans (IDS/IPS awareness)

Nesta fase, utilizei IA como ferramenta de apoio para:

* acelerar desenvolvimento
* explorar melhorias arquiteturais
* refinar a lógica de análise

Todas as decisões técnicas e entendimento do sistema foram conduzidos manualmente.

---

## ⚙️ Arquitetura

### 🔹 Núcleo (C++)

* Gerenciamento de processos com `fork()` + `execvp()`
* Interpretação e execução de comandos
* Sistema de atalhos para Nmap
* Logging em tempo real

### 🔹 Camada de Análise (Python)

* Motor heurístico (regex + scoring)
* Classificação de risco
* Detecção de padrões suspeitos
* Análise de comportamento de scans

---

## 🛡️ Sistema de Classificação

| Nível      | Descrição                    |
| ---------- | ---------------------------- |
| ✅ SAFE     | Execução segura              |
| ⚠️ WARNING | Pode causar impacto          |
| 🚨 DANGER  | Requer confirmação explícita |
| 🔴 BLOCK   | Comando bloqueado            |

---

## 📡 Integração com Nmap

Atalhos disponíveis:

* `scan-fast` → Scan rápido
* `scan-stealth` → Scan furtivo
* `scan-full` → Scan completo (alto ruído)
* `scan-vuln` → Scripts de vulnerabilidade

O sistema também classifica automaticamente o nível de ruído, simulando detecção por IDS/SIEM.

---

## 📁 Estrutura de Logs

* `log.txt` → Histórico de comandos
* `security_log.json` → Análise estruturada
* `nmap_results/` → Resultados dos scans

---

## 🎯 Objetivos

* Consolidar conhecimentos de sistemas Unix
* Explorar conceitos de segurança ofensiva
* Simular análise de risco em tempo real
* Integrar automação com consciência de segurança

---

## ⚠️ Aviso

Este projeto é educacional.

Ferramentas de rede devem ser utilizadas apenas em ambientes autorizados.

---

## 🔮 Próximos Passos

* Execução em sandbox (Docker / namespaces)
* Análise de comandos em sequência (session-aware)
* Interface interativa mais avançada
* Integração opcional com modelos de linguagem locais

---

## 👨‍💻 Sobre o Desenvolvimento

Este projeto segue uma abordagem moderna:

> Combinar fundamentos sólidos de sistemas com uso estratégico de IA como ferramenta de engenharia.

---

## ⭐ Conclusão

CatLine não é apenas um shell.

É uma exploração prática de como sistemas podem evoluir para se tornarem mais conscientes, seguros e contextuais.
