# HU260 — OTEL Passthrough: gRPC + HTTP listeners

## Contexto
- **Notion**: Backlog > HU260
- **Track**: Security-Critical
- **Repo**: dodo_agent
- **Branch**: feat/HU260-otel-passthrough
- **Spec**: `dodo_product/backlog/fase-mvp-integracoes.md`

## User Story
**Como** engenheiro de software com app instrumentada com OpenTelemetry
**Quero** que o agent escute em localhost:4317 (gRPC) e localhost:4318 (HTTP) para receber traces, metricas e logs OTEL
**Para** que qualquer app instrumentada com OTEL possa enviar telemetria para o DoDo sem SDK customizado

## Decisoes Tecnicas

| Decisao | Justificativa | Referencia |
|---------|---------------|------------|
| Proto types inline com prost | Evita dependencia de opentelemetry-proto crate, controle total dos campos necessarios | otel.rs:otlp module |
| gRPC via hyper HTTP/2 raw | tonic server generation exige proto codegen; raw hyper e mais simples para 3 endpoints | otel.rs:grpc_server |
| axum para HTTP listener | Framework leve, composable, suporta graceful shutdown nativo | otel.rs:http_server |
| CancellationToken + Drop | Garante shutdown limpo dos listeners quando scheduler aborta o collector | otel.rs:OtelCollector::drop |
| Bounded channel (10K) | Previne OOM sob carga; RESOURCE_EXHAUSTED/429 quando cheio | otel.rs:BUFFER_CAPACITY |
| Rate limit via AtomicU64 | Counter resetado a cada segundo; low overhead, sem mutex | otel.rs:rate_limit_reset_loop |

## Acceptance Criteria

- [x] AC1: DADO app Python com opentelemetry-sdk apontando para localhost:4317 QUANDO envia spans ENTAO spans aparecem como TracePayload no pipeline
- [x] AC2: DADO app enviando metricas OTEL via HTTP localhost:4318/v1/metrics QUANDO agent recebe ENTAO MetricPayload gerados com labels corretos
- [x] AC3: DADO agent variante lite QUANDO feature OTEL desabilitada ENTAO portas 4317/4318 NAO sao abertas
- [x] AC4: DADO buffer cheio (10.000 envelopes) QUANDO client OTEL envia ENTAO recebe RESOURCE_EXHAUSTED (gRPC) ou 429 (HTTP)
- [x] AC5: DADO agent em shutdown QUANDO OTEL listeners param ENTAO buffer e drenado antes de fechar

## Threat Assessment (STRIDE)

| Ameaca | Risco | Mitigacao | Referencia |
|--------|-------|-----------|------------|
| Spoofing | Medio | Bind exclusivo 127.0.0.1 — sem acesso externo | otel.rs:GRPC_LISTEN_ADDR, assert is_loopback |
| Tampering | Baixo | Dados locais, mTLS para envio upstream | N/A |
| Repudiation | Baixo | Metricas internas otel.requests_total registram atividade | otel.rs:OtelMetrics |
| Information Disclosure | Baixo | Nenhum dado sensivel exposto nos listeners | N/A |
| Denial of Service | Alto | Rate limiting (50K/s), buffer bounded (10K), timeout no scheduler | otel.rs:DEFAULT_RATE_LIMIT_PER_SEC |
| Elevation of Privilege | Baixo | Listeners sao read-only (recebem dados, nao executam acoes) | N/A |

## SACs (Security Acceptance Criteria)

- [x] SAC1: DADO listener gRPC QUANDO bind ENTAO endereco DEVE ser 127.0.0.1 (assert no codigo)
- [x] SAC2: DADO listener HTTP QUANDO bind ENTAO endereco DEVE ser 127.0.0.1
- [x] SAC3: DADO carga acima de 50K envelopes/s QUANDO rate limit ativo ENTAO excedente e rejeitado
- [x] SAC4: DADO feature otel desabilitada QUANDO agent inicia ENTAO nenhum socket e aberto

## Tasks
1. [x] Definir tipos OTLP inline com prost (traces, metrics, logs) — AC1, AC2
2. [x] Implementar conversao OTLP → Envelope (traces, metrics, logs) — AC1, AC2
3. [x] Implementar gRPC server via hyper HTTP/2 — AC1, SAC1
4. [x] Implementar HTTP server via axum — AC2, SAC2
5. [x] Buffer bounded + rate limiting — AC4, SAC3
6. [x] Feature flag otel + cfg gates — AC3, SAC4
7. [x] Graceful shutdown via CancellationToken — AC5
8. [x] Metricas internas (otel.requests_total, etc.) — AC1
9. [x] Testes unitarios (conversao, buffer, rate limit)

## Arquivos Envolvidos
- `crates/agent-collectors/src/otel.rs` — Implementacao completa (substituiu stub)
- `crates/agent-collectors/src/helpers.rs` — Adicionado trace_envelope helper
- `crates/agent-collectors/Cargo.toml` — Feature `otel` com deps axum, prost-types
- `Cargo.toml` — Feature `otel` no workspace + binary
- `src/main.rs` — Registration atualizado (novo constructor)
- `config/agent.yaml` — Config entry para OTEL

## Story History
- HU027: Stub original criado com plan de implementacao
- HU260: Implementacao funcional completa substituindo o stub
