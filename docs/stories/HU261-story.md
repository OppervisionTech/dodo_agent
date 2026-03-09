# HU261 — Docker Container Collector

## Contexto
- **Track**: Security-Critical
- **Repo**: dodo_agent
- **Branch**: feat/HU261-docker-collector
- **Spec**: `dodo_product/backlog/fase-mvp-integracoes.md`

## User Story
**Como** operador SRE monitorando VPS com multiplos containers Docker
**Quero** que o agent colete metricas por container automaticamente quando Docker presente
**Para** ver a saude de cada container individualmente no dashboard

## Decisoes Tecnicas

| Decisao | Justificativa | Referencia |
|---------|---------------|------------|
| Raw HTTP over Unix socket | Evita dependencia de crate Docker; API e simple (GET + JSON) | docker.rs:docker_get |
| Connection: close | Evita chunked encoding complexo; garante read_to_end funcione | docker.rs:docker_get |
| Delta state por container_id | HashMap<String, PreviousContainerState> para rede/disco | docker.rs:PreviousState |
| Auto-detect docker.sock | Se socket nao existe, collector fica inativo sem erro | docker.rs:docker_available |
| Cleanup de containers removidos | prev_guard.retain() limpa estado de containers que desapareceram | docker.rs:collect_impl |

## Threat Assessment (STRIDE)

| Ameaca | Risco | Mitigacao |
|--------|-------|-----------|
| Information Disclosure | Alto | NUNCA expor env vars de containers; NUNCA logar comandos/entrypoints |
| Denial of Service | Medio | Timeout em docker_get; se Docker slow, nao bloqueia agent |
| Elevation of Privilege | Baixo | Read-only: apenas GET, nunca POST/PUT/DELETE na Docker API |

## SACs
- [x] SAC1: DADO container com env vars contendo SECRET_KEY QUANDO agent coleta ENTAO env vars NAO aparecem em nenhum payload
- [x] SAC2: DADO docker.sock sem permissao QUANDO agent tenta conectar ENTAO warning no log e collector desativado

## Arquivos Envolvidos
- `crates/agent-collectors/src/docker.rs` — Novo modulo completo
- `crates/agent-collectors/src/lib.rs` — Module declaration
- `crates/agent-collectors/Cargo.toml` — Feature `docker`
- `Cargo.toml` — Feature propagation
- `src/main.rs` — Registration
- `crates/agent-config/src/lib.rs` — Default config
- `config/agent.yaml` — YAML entry
