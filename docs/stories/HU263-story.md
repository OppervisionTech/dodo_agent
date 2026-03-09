# HU263 — Redis Collector

## Contexto
- **Track**: Security-Critical
- **Repo**: dodo_agent
- **Branch**: feat/HU263-redis-collector
- **Spec**: `dodo_product/backlog/fase-mvp-integracoes.md`

## User Story
**Como** operador SRE monitorando Redis como cache/fila
**Quero** que o agent colete metricas do Redis quando configurado
**Para** ver se o cache esta saudavel, se ha evictions excessivas, memoria no limite

## Decisoes Tecnicas

| Decisao | Justificativa | Referencia |
|---------|---------------|------------|
| RESP manual | Protocolo e trivial para INFO; evita dependencia do crate redis | redis_collector.rs:resp_command |
| URL parser manual | Suporta redis://[:pass@]host:port e host:port simples | redis_collector.rs:parse_redis_url |
| Connection per collect | Redis INFO e rapido (~1ms); nova conexao a cada 10s e aceitavel | redis_collector.rs:collect_impl |
| Delta para hits/misses/evictions | Hit ratio calculado sobre deltas, nao cumulativo | redis_collector.rs:PreviousState |
| Keyspace parsing manual | db0:keys=X,expires=Y format parseado para total_keys/total_expires | redis_collector.rs:keyspace |

## Threat Assessment (STRIDE)

| Ameaca | Risco | Mitigacao |
|--------|-------|-----------|
| Information Disclosure | Critico | URL NUNCA logada (pode conter senha) |
| Spoofing | Baixo | Conexao direta, sem proxy; AUTH se configurado |
| Denial of Service | Baixo | INFO e comando leve; timeout de 5s |

## SACs
- [x] SAC1: DADO URL com senha QUANDO agent coleta ENTAO URL NAO aparece em logs
- [x] SAC2: DADO Redis offline QUANDO agent tenta conectar ENTAO warning e retry no proximo ciclo
- [x] SAC3: DADO URL nao configurado QUANDO agent inicia ENTAO coletor inativo sem erro

## Arquivos Envolvidos
- `crates/agent-collectors/src/redis_collector.rs` — Redis collector completo
- `crates/agent-collectors/src/lib.rs` — Module declaration
- `crates/agent-collectors/Cargo.toml` — Feature redis-collector
- `Cargo.toml` — Feature propagation
- `src/main.rs` — Registration
- `crates/agent-config/src/lib.rs` — Default config
- `config/agent.yaml` — YAML entry
