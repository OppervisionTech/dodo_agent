# dodo_agent — Agent de Coleta (Rust)

> **Stack**: Rust (Edition 2021)
> **Fase**: MVP
> **Depende de**: dodo_proto
> **Referência**: Arquitetura Parte 1 (Fontes de dados) + Parte 2 (Agent) + Agent Spec v0.4

---

## Responsabilidade

Binário Rust que roda em cada host monitorado. Coleta todos os sinais de telemetria, empacota em AgentEnvelope (Protobuf), e envia via gRPC+mTLS para o Kong na porta 443. É o único ponto de entrada de dados no pipeline AegisOps.

---

## 3 Variantes (mesmo codebase, feature flags)

| Variante | Target | eBPF | Compressão | RAM | CPU idle |
|----------|--------|------|------------|-----|----------|
| `aegis-agent` | Linux (VM, Bare Metal, K8s) | Sim (kernel >= 5.8) | zstd | < 50MB | < 0.8% |
| `aegis-agent-windows` | Windows Server/Desktop | ETW substitui eBPF | zstd | < 80MB | < 1% |
| `aegis-agent-lite` | IoT/Edge (ARM, MIPS, RISC-V) | Não | lz4 | < 20MB | < 0.5% |

---

## 13 Categorias de Coletores

| # | Coletor | Intervalo | Fonte |
|---|---------|-----------|-------|
| 5.1 | CPU & Compute | 5s | /proc/stat, cgroups |
| 5.2 | Memory & Swap | 5s | /proc/meminfo, cgroups |
| 5.3 | Processos & Runtime | 10s poll + real-time eBPF | /proc, eBPF execve |
| 5.4 | Rede & Tráfego | 5s + flows 10s | /proc/net, eBPF socket/tc |
| 5.5 | Segurança & Portas | 15s snapshot + real-time | inotify, eBPF, auditd |
| 5.6 | Certificados TLS/PKI | 1h + evento em mudança | TLS handshake, /etc/ssl, K8s secrets |
| 5.7 | Disco & I/O | 10s | /proc/diskstats, SMART |
| 5.8 | Logs & Journaling | streaming contínuo | journald, syslog, application logs |
| 5.9 | OTEL Passthrough | contínuo | localhost:4317 (gRPC) / 4318 (HTTP) |
| 5.10 | AegisOps SDK | contínuo | localhost:4317 / 4318 |
| 5.11 | Kubernetes & Containers | 15s poll + real-time | K8s API, cAdvisor, eBPF |
| 5.12 | Inventário & Identidade | boot + 1h | /etc, IMDSv2, WMI |
| 5.13 | Auto-observabilidade | 30s | métricas internas do agent |

---

## Comportamento Core

### Identidade
- Primeiro boot: gera `agent_id` (UUID v4) gravado em disco permanentemente
- Identifica o agent em todas as comunicações futuras

### Batching & Envio
- Buffer interno: flush a cada 5s OU quando atinge 500 sinais
- Compressão antes do envio (zstd para linux/windows, lz4 para lite)
- Envio via gRPC + Protobuf + mTLS para Kong:443

### Buffer Local (resiliência)
- Se Kong indisponível: buffer em disco (512MB padrão)
- Prioridade de envio ao reconectar: security > heartbeat > metrics > logs
- Dados marcados com `buffered: true` e `retry_count`

### Config Pull
- GET para Kong a cada 60s buscando atualizações
- Se config_hash mudou: hot reload sem restart
- Configuração em YAML local + override remoto

### Segurança
- mTLS obrigatório (certificado por agent, CA interna AegisOps)
- Env vars SEMPRE redactadas antes de sair do host
- Agent NUNCA escuta na rede (apenas localhost para SDK/OTEL)
- Em K8s: ServiceAccount read-only, nunca escreve no cluster

---

## Estrutura do projeto

```
dodo_agent/
├── Cargo.toml                     # Workspace com feature flags
├── crates/
│   ├── agent-core/                # Loop principal, scheduler, batching
│   ├── agent-collectors/          # Cada coletor como módulo
│   │   ├── cpu.rs
│   │   ├── memory.rs
│   │   ├── disk.rs
│   │   ├── network.rs
│   │   ├── process.rs
│   │   ├── security.rs
│   │   ├── certs.rs
│   │   ├── logs.rs
│   │   ├── otel.rs
│   │   ├── kubernetes.rs
│   │   ├── inventory.rs
│   │   └── self_metrics.rs
│   ├── agent-transport/           # gRPC client, mTLS, buffer local
│   ├── agent-config/              # Parsing YAML, hot reload
│   ├── agent-ebpf/                # Programas eBPF (feature-gated)
│   └── agent-platform/            # Abstrações por OS (linux/windows/lite)
├── proto/                         # Link para dodo_proto
└── tests/
```

---

## Convenções Rust

- `cargo clippy` sem warnings em CI
- `cargo fmt` obrigatório
- Sem `unsafe` sem justificativa documentada e aprovada no story file
- Error types com `thiserror`, propagação com `?`
- Sem `unwrap()` em código de produção (usar `expect()` com mensagem ou `?`)
- Async com `tokio` runtime
- Cada coletor implementa trait `Collector`
- Testes com `#[tokio::test]` para código async


---

## Oppervision Flow

Este repo segue o **Oppervision Flow** (6 fases). Documentação completa na raiz do projeto:

- **Metodologia**: `docs/flow/overview.md`
- **Templates**: `docs/templates/` (story file, PR, threat model, review checklist)
- **Referência completa**: `CLAUDE.md` raiz — Seções 5 a 7

### Fases

```
0. REFINE → 1. SPEC → 2. THREAT → 3. IMPLEMENT → 4. REVIEW → 5. DELIVER
```

### Track padrão: Security-Critical

Este repo lida com **dados sensíveis, autenticação, execução em produção ou superfície de ataque exposta**. Todas as HUs deste repo seguem obrigatoriamente o track Security-Critical:

```
SPEC → THREAT (STRIDE obrigatório) → IMPLEMENT → REVIEW (adversarial) → DELIVER
```

- Threat model STRIDE completo antes de implementar
- Review adversarial (2 reviewers, checklist de segurança completo)
- Nenhuma exceção — toda mudança passa por THREAT

### Regras inegociáveis

- **Toda feature começa com HU no Notion** (formato CQPD: Como/Quero/Para/Deve)
- **Story file obrigatório** antes de escrever código (`docs/templates/story.md`)
- **Threat assessment (STRIDE) obrigatório** para este repo
- **PR usa template padrão** (`docs/templates/pr-template.md`)
- **Review checklist** por stack (`docs/templates/review-checklist.md`)
- **Nada fica para "depois"** — cada HU é completa ou não entra no sprint

---

## Git Workflow

### Main-First Strategy

- `main` é **sempre production-ready**
- Features SEMPRE criam branch a partir de `main`
- PR direto para `main` (sem develop, staging, etc.)
- Squash merge para manter histórico limpo

### Branch Naming

```
feat/HU{N}-descricao-curta
fix/HU{N}-descricao-curta
refactor/HU{N}-descricao-curta
```

### Commits

```
tipo(escopo): descrição curta

Corpo opcional com contexto.

Refs: HU{N}
```

Tipos: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `chore`

### Antes de abrir PR

1. `git fetch origin && git rebase origin/main`
2. CI passa (lint, test, build)
3. Story file atualizado com decisões técnicas
4. Self-review pelo dev
5. Threat model revisado (Security-Critical)
