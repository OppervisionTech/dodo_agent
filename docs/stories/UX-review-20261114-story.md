# Review DodoTestStg — identidade de host estável em container (Fase 2)

Track: Security-Critical. Plano aprovado pelo usuário em 2026-11-14 (`~/.claude/plans/pegue-o-plano-pasted-content-dapper-tarjan.md`, review da org DodoTestStg). HU a confirmar no Notion — o número não foi informado; a branch usa nome descritivo até lá. Branch `feat/stable-host-identity`.

## User story
Como quem roda o agent em Docker, quero que a máquina mantenha uma única identidade entre recriações do container, para não aparecer como um host novo a cada vez.

## Achado
Sem `/etc/machine-id` do host e sem volume em `/var/lib/aegis`, o agent gera um `host-id` novo a cada recriação. Em k8s (stg) isso já está resolvido: `NODE_NAME` e hostPath persistente.

## Critérios de aceite
- **AC1.** `DODO_HOST_ID` válido (1–128 caracteres de `[A-Za-z0-9._-]`) tem precedência sobre machine-id e sobre o arquivo persistido.
- **AC2.** Valor inválido é ignorado com aviso no log; o agent segue com a resolução normal (não falha a inicialização).
- **AC3.** Ao **gerar** uma identidade nova, o agent avisa no log que ela depende do arquivo e como fixá-la.
- **AC4.** Sem a variável, o comportamento não muda.

## STRIDE
| Ameaça | Controle / teste |
|---|---|
| Spoofing | Quem define a variável já controla o processo do agent e seus arquivos de identidade; não há ganho novo. O vínculo agent↔org continua sendo a API key e a chave pública no enrollment (ingestor), não o `host_id`. |
| Tampering | Lista de caracteres restrita e tamanho limitado: o valor vai para labels e consultas, não pode carregar separadores, espaços ou caminho. |
| Information disclosure | O log de aviso traz o caminho do arquivo, não o valor da identidade. |
| Denial of service | Dois hosts com o mesmo `DODO_HOST_ID` na mesma org passam a contar como um: é erro de configuração do operador, restrito à própria org. Documentar. |
| Elevation of privilege | Nenhuma permissão nova; sem `unsafe`. |

## Arquivos
`crates/agent-platform/src/common.rs` (+ teste).

## Validação
`cargo test -p agent-platform --lib common` (3 passando) e `cargo fmt`. Faltam `cargo clippy`, a suíte completa e documentar a variável no guia de instalação. Exige release do agent para ter efeito.
