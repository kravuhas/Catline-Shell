# 🔐 CatLine Security Shell — Nmap Red Team Edition

CatLine é um shell customizado em C++ com foco em segurança ofensiva (Red Team) e análise de risco em tempo real.

O projeto foi desenvolvido com o objetivo de explorar como um terminal pode ir além da simples execução de comandos, incorporando consciência de segurança, classificação de risco e suporte a auditoria de rede.

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

Este projeto não é apenas sobre execução de comandos.

Ele representa a ideia de:

> “Um sistema que entende o impacto do que está sendo executado.”

Além disso, o desenvolvimento foi feito utilizando IA como ferramenta de apoio — não como substituição de conhecimento.

A IA foi usada para:

* acelerar desenvolvimento
* explorar ideias de arquitetura
* refinar lógica de segurança

Mas todas as decisões estruturais e entendimento técnico foram guiados manualmente.

---

## ⚙️ Arquitetura

### 🔹 Núcleo (C++)

* Gerenciamento de processos com `fork()` + `execvp()`
* Interpretação de comandos
* Sistema de atalhos para Nmap
* Logging em tempo real

### 🔹 Camada de Análise (Python)

* Motor heurístico baseado em regras (regex + scoring)
* Classificação de risco de comandos
* Detecção de padrões suspeitos
* Análise de “ruído” de scans (IDS/IPS awareness)

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

O CatLine inclui atalhos inteligentes para scans, como:

* `scan-fast` → Scan rápido
* `scan-stealth` → Scan furtivo com evasão
* `scan-full` → Scan completo (alto ruído)
* `scan-vuln` → Scripts de vulnerabilidade

Além disso, o sistema classifica automaticamente o nível de “ruído” do scan, simulando detecção por IDS/SIEM.

---

## 📁 Estrutura de Logs

* `log.txt` → Histórico de comandos
* `security_log.json` → Análise estruturada
* `nmap_results/` → Resultados dos scans

---

## 🎯 Objetivo

Este projeto foi criado para:

* Aprender conceitos de sistemas Unix (processos, exec)
* Explorar segurança ofensiva (Red Team mindset)
* Simular análise de risco em tempo real
* Integrar automação com consciência de segurança

---

## ⚠️ Aviso

Este projeto é destinado exclusivamente para fins educacionais.

Qualquer uso de ferramentas de rede deve ser feito apenas em ambientes autorizados.

---

## 🧪 Evolução

O projeto começou como um shell extremamente simples:

* leitura de input
* execução com `execvp`

E evoluiu para um sistema com:

* análise de risco
* logging estruturado
* integração com ferramentas de segurança

---

## 🔮 Futuro

Possíveis melhorias:

* Integração com LLM local (ex: análise contextual)
* Execução em sandbox (Docker / namespaces)
* Detecção de comportamento em sequência (session-aware)
* Interface interativa mais avançada

---

## 👨‍💻 Sobre o desenvolvimento

Este projeto reflete uma abordagem moderna de aprendizado:

> Não apenas programar, mas entender sistemas e usar IA como ferramenta para acelerar evolução.

---

## ⭐ Conclusão

CatLine não é apenas um shell.

É um experimento de como terminais podem evoluir para sistemas conscientes de segurança.

---
