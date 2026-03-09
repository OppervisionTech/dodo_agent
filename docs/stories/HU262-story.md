# HU262 — PostgreSQL + MongoDB Collectors

## Contexto
- **Track**: Security-Critical
- **Repo**: dodo_agent
- **Branch**: feat/HU262-database-collectors
- **Spec**: `dodo_product/backlog/fase-mvp-integracoes.md`

## User Story
**Como** operador SRE monitorando bancos de dados
**Quero** que o agent colete metricas de PostgreSQL e MongoDB quando configurados
**Para** detectar problemas (connection exhaustion, slow queries, replication lag) antes de impactar usuarios

## Decisoes Tecnicas

| Decisao | Justificativa | Referencia |
|---------|---------------|------------|
| tokio-postgres (PG) | Driver async leve, ideal para SELECT em views de estatistica | postgres.rs |
| mongodb crate (Mongo) | Driver oficial, necessario para wire protocol e serverStatus | mongodb_collector.rs |
| Env vars para DSN/URI | Config segura sem hardcode; collector inativo se nao configurado | postgres.rs:DSN_ENV_VAR |
| Persistent connection | 1 conexao mantida entre coletas; reconecta se cair | postgres.rs:ensure_connection |
| Delta calculations | Counters (transactions, tuples, opcounters) reportados como deltas | postgres.rs:PreviousState |
| Feature flags | postgres/mongodb features evitam compilar drivers quando nao necessario | Cargo.toml |

## Threat Assessment (STRIDE)

| Ameaca | Risco | Mitigacao |
|--------|-------|-----------|
| Information Disclosure | Critico | DSN/URI NUNCA logados; redaction obrigatoria | postgres.rs, mongodb_collector.rs |
| Spoofing | Medio | Usuario do banco deve ser read-only (pg_monitor / clusterMonitor) |
| Denial of Service | Baixo | 1 conexao persistente; queries leves em views de stats |

## SACs
- [x] SAC1: DADO DSN com senha QUANDO agent loga config ENTAO senha NAO aparece em logs
- [x] SAC2: DADO PostgreSQL/MongoDB offline QUANDO agent tenta conectar ENTAO log warning e retry (nao crashar)
- [x] SAC3: DADO DSN/URI nao configurado QUANDO agent inicia ENTAO coletores inativos sem erro

## Arquivos Envolvidos
- `crates/agent-collectors/src/postgres.rs` — PostgreSQL collector completo
- `crates/agent-collectors/src/mongodb_collector.rs` — MongoDB collector completo
- `crates/agent-collectors/src/lib.rs` — Module declarations
- `crates/agent-collectors/Cargo.toml` — Features postgres, mongodb com deps
- `Cargo.toml` — Feature propagation + workspace deps
- `src/main.rs` — Registration
- `crates/agent-config/src/lib.rs` — Default config entries
- `config/agent.yaml` — YAML entries
