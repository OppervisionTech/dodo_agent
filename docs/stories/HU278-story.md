# HU278 (agent) — Coletor Kubernetes real: rollouts e recursos de pods

## Contexto
- **Track**: Security-Critical
- **Branch**: feat/HU278-incident-flow-real (a partir de `develop`)
- **HU localmente inferida** (sem Notion): HU278 é o fluxo de incidente real descrito em
  `dodo_ai_core/docs/stories/HU278-story.md`. Esta story cobre só a parte do agente.
- O `kubernetes.rs` era um stub ("MVP stub") que só emitia `kubernetes.collector.active`.

## User Story
**Como** time que roda serviços em Kubernetes monitorados pelo dodo
**Quero** que o agente perceba cada rollout (troca de imagem) e informe requests/limits/uso dos pods
**Para** o Aegis correlacionar incidentes com o deploy certo, voltar para a versão anterior e o
FinOps recomendar rightsizing de contêineres com dados reais

### Deve
- Listar Deployments, StatefulSets e DaemonSets pela API in-cluster (ServiceAccount, CA do cluster)
  e emitir `deploy.rollout` (EVENT → tópico `deploy-events` no ingestor) quando as imagens mudam.
  O primeiro scan só memoriza o estado (restart do agente não é rollout).
- A cada minuto: requests/limits por contêiner dos pods **do próprio nó**, uso via metrics.k8s.io
  quando disponível, allocatable e instance type do nó.
- Nenhuma escrita no cluster; nenhuma dependência nova (reqwest já existia).

## Threat model (STRIDE)

| Ameaça | Cenário | Mitigação |
|---|---|---|
| **S**poofing | MITM entre agente e API server devolvendo dados falsos | TLS verificado só contra a CA do service account (`tls_built_in_root_certs(false)`) |
| **T**ampering | Agente alterando o cluster | Só GET; ClusterRole do chart é get/list; nenhum verbo de escrita usado |
| **R**epudiation | — | Eventos carregam workload, revisão e imagens antes/depois |
| **I**nformation disclosure | Vazar segredos de specs (env, args) | Só nome, namespace, labels de app, imagens, revisão e quantidades de recursos saem do host; env/args nunca são lidos |
| **D**enial of service | Clusters grandes / API lenta | `limit=500`, timeout 10s, recursos só do próprio nó e só a cada 4 ticks; falha de um scan não emite nada |
| **E**levation of privilege | Token do SA em logs | Token só em memória; nunca logado |

## Verificação
- `cargo test -p agent-collectors --lib kubernetes` (snapshots, diff de rollouts, versão da imagem,
  quantidades, join requests×uso); `cargo clippy` limpo.
- E2E: rollout do `dummy-app` gera linha em `deploy_events`.
