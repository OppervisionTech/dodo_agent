# HU264 — Limpeza/organização de código: split de arquivos grandes, dedupe, gate de padronização

## Contexto
- **Track**: Security-Critical (obrigatório neste repo)
- **Repo**: dodo_agent
- **Branch**: cleanup/agent-hu264
- **HU localmente inferida**: sem integração com Notion neste ambiente; HU264 é o próximo número livre após HU263 nos story files deste repo (`docs/stories/HU260..263-story.md`). Reconciliar com o Notion real antes do merge.
- **Desvio do Git Workflow documentado**: `CLAUDE.md` (`Main-First Strategy`) diz que branches sempre partem de `main` e que não há `develop`/staging. Na prática, o repo tem uma branch `develop` 26 commits à frente de `main` (`main` tem 0 commits exclusivos — confirmado via `git rev-list --count develop..main` = 0), com CI/CD configurado para disparar em `develop` (`ci(agent): trigger CI on develop branch`, `ci(agent): trigger CD on develop branch for staging deploys`) e fixes reais não presentes em `main` (TLS/mTLS, correções de clippy). `main` está desatualizada na prática. Esta branch parte de `develop` (estado real/deployado), não de `main` (convenção documentada mas não seguida) — reconciliar/atualizar `CLAUDE.md` é uma decisão fora do escopo desta HU, só documentando o desvio aqui.
- **Referência**: plano `/home/enzot/.claude/plans/rode-um-plano-para-logical-pancake.md`, Fase 4.

## User Story
**Como** desenvolvedor mantendo o dodo_agent
**Quero** que o blocker de clippy seja corrigido, duplicação óbvia seja extraída, arquivos grandes (>1000 linhas) sejam organizados, e um gate de padronização exista
**Para** reduzir risco de manutenção num binário que roda como DaemonSet em todo host monitorado em produção

### Deve
- Corrigir blockers de `cargo clippy -D warnings` nas 3 combinações de feature (linux/lite/windows)
- Extrair duplicação mecânica de baixo risco (retry, padrão de client factory)
- Avaliar split de `otel.rs`/`main.rs`/`linux/mod.rs`/`lite/mod.rs` — só executar com rede de segurança de teste, migrando função por função com checkpoint de build+test+clippy nas 3 features a cada passo
- Nenhuma mudança de comportamento visível (parsing de métricas, formato OTLP exportado, comandos aceitos)

### Não faz parte desta HU
- Otimizações de performance (shell-out síncrono para `curl` em vez de `reqwest` em `linux/mod.rs`) — só observar
- Extração de funções puras de parsing compartilhadas entre `linux/mod.rs` e `lite/mod.rs` SEM antes ter fixtures de teste reais de `/proc` cobrindo o comportamento atual — se não houver tempo/fixtures suficientes nesta rodada, fica como item futuro documentado, não forçado

## Baseline real (corrigida na execução)

O plano de referência assumia que o único blocker de clippy eram 2 warnings em
`agent-ebpf` (imports `info`/`warn` não usados + falta de `impl Default`) nas
features `lite`/`windows`. Rodando `cargo clippy --workspace --all-targets
--no-default-features --features <f> -- -D warnings` fresco nas 3 combinações,
a baseline real é:

| Feature | Erros |
|---|---|
| `linux` | 1: `agent-config/src/merger.rs:51` — `field_reassign_with_default` (só no módulo de teste) |
| `lite` | 3: os 2 de `agent-ebpf` (confirma o plano) + o mesmo de `agent-config/src/merger.rs` |
| `windows` | 3: mesmos 2 de `agent-ebpf` + mesmo de `agent-config/src/merger.rs` |

O erro em `agent-config/src/merger.rs` não estava no plano original — presente
nas 3 features (código não é feature-gated), então corrigi-lo desbloqueia as
3 combinações de uma vez. Os 2 erros de `agent-ebpf` só afetam `lite`/`windows`
(sob `linux`, o crate usa uma implementação real de eBPF onde os imports
`info`/`warn` são de fato usados — confirmar ao ler o código).

## Threat Model (STRIDE) — resumo

Split/dedupe mecânico num binário que roda como DaemonSet com privilégios
elevados (leitura de `/proc`, sockets, possivelmente eBPF) em todo host
monitorado em produção.

| Pergunta STRIDE | Análise |
|---|---|
| **Spoofing** | Sem mudança em autenticação (mTLS/JWT do agent para o backend, HU já resolvida em `1fb3195`) — fora do escopo, não tocado. |
| **Tampering** | Risco central: extração de funções de parsing (`/proc`, RESP do Redis, etc.) pode alterar sutilmente o resultado parseado sem gerar erro de compilação — só um teste comparando struct antes/depois pega isso. Mitigação: só extrair com fixtures reais cobrindo o comportamento atual, migração função por função. |
| **Repudiation** | N/A — este split não toca em audit trail/logging estruturado. |
| **Information Disclosure** | Risco a vigiar: se algum split expuser (`pub` em vez de `pub(crate)`) um campo/struct que hoje é privado e contém dado sensível (ex. URL do Redis com senha, já mitigado hoje por nunca ser logada) — checar visibilidade ao mover código entre módulos. |
| **Denial of Service** | A matriz de build (3 features) e a suíte de testes existem exatamente para pegar isso — checkpoint obrigatório de `cargo build --release` + `cargo test` nas 3 features a cada função migrada, não só no final. |
| **Elevation of Privilege** | Sem mudança em como o agent decide o que coletar/executar — puramente reorganização de código, sem lógica de decisão nova. |

**Conclusão**: risco concentrado em extrações de parsing que tocam
`linux/mod.rs`/`lite/mod.rs` (maior risco do plano inteiro, per o próprio
plano de referência) — mitigado por rede de segurança de teste obrigatória
antes de mover, migração função por função, e reversão do commit se qualquer
combinação de feature quebrar.

## Plano de referência

Ver `/home/enzot/.claude/plans/rode-um-plano-para-logical-pancake.md`, Fase 4.
