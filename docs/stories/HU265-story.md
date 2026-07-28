# HU265 — Corrigir vulnerabilidades e débitos apontados pelo `cargo audit`

## Contexto
- **Track**: Security-Critical (obrigatório neste repo)
- **Repo**: dodo_agent
- **Branch**: fix/HU265-security-audit-vulnerabilities
- **HU localmente inferida**: sem integração com Notion neste ambiente; HU265 é o próximo número livre após HU264 nos story files deste repo (`docs/stories/HU260..264-story.md`). Reconciliar com o Notion real antes do merge.
- **Origem**: o gate `Security Audit` (`cargo audit`, job do `agent-ci.yml`) está falhando em `develop` desde antes desta sessão (confirmado: runs de 2026-07-27 já falhavam com o mesmo resultado, não é regressão da HU264). Ao habilitar o disparo de CI em PRs contra `develop` (HU264/fix de trigger), o mesmo estado vermelho passou a aparecer também no PR da HU264. Aberta como HU separada em vez de expandir o escopo da HU264, seguindo o mesmo padrão já usado para a HU105 (cobertura) em dodo_ai_core.
- **Referência**: run que expôs o achado — `gh run view 30398706760` (branch `develop`, job `Security Audit`).

## User Story
**Como** desenvolvedor mantendo o dodo_agent
**Quero** que o `cargo audit` do CI passe (ou que os achados sem correção disponível fiquem formalmente documentados como risco aceito, com justificativa e revisão periódica)
**Para** que o gate de segurança do binário que roda como DaemonSet privilegiado em produção volte a ser confiável como sinal, em vez de permanecer cronicamente vermelho

### Deve
- Atualizar `crossbeam-epoch` para `>=0.9.20` (corrige `RUSTSEC-2026-0204` — dereferência de ponteiro inválido em `fmt::Pointer`)
- Atualizar `quinn-proto` para `>=0.11.15` (corrige `RUSTSEC-2026-0185` — exaustão de memória remota via reassembly de stream fora de ordem sem limite, severidade 7.5/high)
- Para os 4 avisos sem correção disponível hoje (`rustls-pemfile` 2.2.0 unmaintained/`RUSTSEC-2025-0134`; `anyhow` 1.0.102 unsound/`RUSTSEC-2026-0190`; `rand` 0.8.5 e `rand` 0.9.2 unsound/`RUSTSEC-2026-0097`): decidir, por crate, entre (a) migrar para alternativa mantida, (b) aceitar o risco formalmente via `.cargo/audit.toml` (`ignore = [...]`) com comentário justificando e data de revisão, ou (c) aguardar patch upstream — registrar a decisão tomada para cada um
- Rodar a matriz completa (`cargo build`/`test`/`clippy` nas 3 features) após qualquer bump de versão, antes de considerar a HU concluída
- Confirmar se `quinn-proto`/`crossbeam-epoch` são dependências transitivas (via `agent-transport`, aparentemente QUIC) e se o bump é resolvível só com `cargo update -p <crate>` (sem subir a dependência direta que os traz) ou se exige subir algo em `Cargo.toml`

### Não faz parte desta HU
- Qualquer mudança de comportamento do transporte/protocolo além do bump de versão em si
- Split/dedupe de código (isso é HU264, já concluída)
- Migrar `anyhow`/`rand` para outra crate, a menos que a decisão do item acima aponte para isso — não assumir essa migração como certa de antemão

## Baseline (achado em `develop`, run `30398706760`)

`cargo audit` escaneou 406 dependências no `Cargo.lock` e retornou 2 erros (bloqueiam o gate) + 4 avisos (não bloqueiam, mas aparecem no output):

| Crate | Versão | Tipo | Advisory | Severidade | Correção disponível |
|---|---|---|---|---|---|
| `crossbeam-epoch` | 0.9.18 | vulnerabilidade | RUSTSEC-2026-0204 | — | Sim — `>=0.9.20` |
| `quinn-proto` | 0.11.14 | vulnerabilidade | RUSTSEC-2026-0185 | 7.5 (high) | Sim — `>=0.11.15` |
| `rustls-pemfile` | 2.2.0 | unmaintained | RUSTSEC-2025-0134 | — | Não |
| `anyhow` | 1.0.102 | unsound | RUSTSEC-2026-0190 | — | Não |
| `rand` | 0.8.5 | unsound | RUSTSEC-2026-0097 | — | Não |
| `rand` | 0.9.2 | unsound | RUSTSEC-2026-0097 | — | Não |

Observações de proveniência (via `Cargo.lock`/`Cargo.toml`):
- `anyhow` é dependência direta do workspace (`Cargo.toml:38`, `anyhow = "1"`), consumida por `agent-command`, `agent-collectors`, `agent-config`, `agent-ebpf`, `agent-transport`, `agent-core`.
- `crossbeam-epoch` e `quinn-proto` não aparecem como dependências diretas em nenhum `Cargo.toml` do workspace — são transitivas, provavelmente via a stack QUIC usada por `agent-transport` (a confirmar com `cargo tree -i` na implementação).
- `rand` aparece em 3 versões simultâneas no lockfile (0.8.5, 0.9.2, 0.10.1) — fragmentação de versão entre dependências transitivas, não um único ponto de bump.

## Threat Model (STRIDE) — resumo

Bump de dependências num binário que roda como DaemonSet privilegiado em todo host monitorado em produção; toca a stack de transporte (QUIC/TLS) que carrega telemetria e comandos.

| Pergunta STRIDE | Análise |
|---|---|
| **Spoofing** | Sem mudança na lógica de mTLS/JWT do agent (HU já resolvida em `1fb3195`) — só a versão da lib QUIC subjacente muda, não o protocolo de handshake. |
| **Tampering** | O bug do `quinn-proto` (reassembly de stream fora de ordem) é justamente uma superfície de tampering/robustez de protocolo — corrigir é redução de risco, não introdução. Verificar que a versão nova não muda formato de frame de forma incompatível com o backend. |
| **Repudiation** | N/A — sem mudança em audit trail. |
| **Information Disclosure** | `crossbeam-epoch`/`rustls-pemfile` tocam memória/parsing de certificado — checar que o bump não altera como material de TLS é mantido em memória de forma que vaze via a mesma classe de bug. |
| **Denial of Service** | Esta é a motivação central da HU: `RUSTSEC-2026-0185` é literalmente um vetor de exaustão de memória remota (severidade 7.5) — corrigir reduz superfície de DoS contra o agent. |
| **Elevation of Privilege** | Sem mudança em como o agent decide o que coletar/executar. |

## Resultado

- `crossbeam-epoch` atualizado 0.9.18 → 0.9.20 via `cargo update -p crossbeam-epoch --precise 0.9.20` (`RUSTSEC-2026-0204` corrigido).
- `quinn-proto` atualizado 0.11.14 → 0.11.15 via `cargo update -p quinn-proto --precise 0.11.15` (`RUSTSEC-2026-0185` corrigido).
- Ambos são dependências transitivas (`crossbeam-epoch` via `moka` → `hickory-resolver` → `mongodb` → `agent-collectors`; `quinn-proto` não aparece na árvore resolvida para nenhum target/feature atual — entrada órfã no lockfile, possivelmente de uma dependência opcional não habilitada por padrão). O bump via `cargo update -p` resolveu ambos sem precisar tocar em nenhum `Cargo.toml` — só `Cargo.lock` mudou (8 linhas).
- `cargo audit` local após o bump: 0 vulnerabilidades, 4 avisos (`rustls-pemfile` unmaintained, `anyhow` unsound, `rand` 0.8.5 e `rand` 0.9.2 unsound) — sem correção disponível hoje em nenhum dos 4. Esses avisos já não bloqueavam o gate (`cargo audit` só retorna exit 1 para vulnerabilidades reais, os 4 aparecem como "allowed warnings"), então nenhuma decisão de `.cargo/audit.toml` foi necessária para desbloquear o CI. Ficam documentados aqui como débito conhecido, sem ação nesta HU — revisar quando houver patch upstream.
- Checkpoint completo rodado: `cargo audit` limpo, `cargo fmt --check` limpo, `cargo clippy -D warnings` limpo nas 3 features (linux/lite/windows), `cargo test --workspace` linux 81/0 e lite 71/0 (mesmos números da baseline da HU264, sem regressão), `cargo build --release` limpo em linux/lite/windows.

## Plano de referência

Sem plano de referência prévio — esta HU nasce do achado do gate `Security Audit`, não do plano de limpeza (`/home/enzot/.claude/plans/rode-um-plano-para-logical-pancake.md`).
