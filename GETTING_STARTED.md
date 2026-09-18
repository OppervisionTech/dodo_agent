# Getting Started — AegisOps Agent

Guia para instalar o agente em qualquer servidor e começar a observar sua aplicação em minutos.

---

## Pré-requisitos

| Requisito | Detalhe |
|-----------|---------|
| **Conta AegisOps** | Crie em [portal.aegisops.io](https://portal.aegisops.io) |
| **API Key** | Gere em **Configurações → API Keys** (formato `aegis_sk_...`) |
| **Sistema operacional** | Linux (amd64/arm64, kernel ≥ 5.8) ou Windows Server 2019+ |
| **Rede** | Porta 443 de saída para `kong.aegisops.io` |

---

## Passo 1 — Instalar o agente

### Linux (recomendado)

```bash
curl -fsSL https://get.aegisops.io/agent | sudo bash \
  --mode server \
  --api-key aegis_sk_SUA_KEY_AQUI
```

O script detecta automaticamente sua distro e arquitetura, baixa o binário correto, cria o serviço systemd e instala certificados mTLS. Nenhuma configuração manual é necessária.

### Docker

```bash
docker run -d \
  --name aegis-agent \
  --network host \
  --pid host \
  --privileged \
  -e DODO_API_KEY=aegis_sk_SUA_KEY_AQUI \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  ghcr.io/oppervisiontech/aegis-agent:latest
```

### Kubernetes

```bash
curl -fsSL https://get.aegisops.io/agent | bash \
  --mode k8s \
  --api-key aegis_sk_SUA_KEY_AQUI \
  --namespace dodo
```

Instala como DaemonSet via Helm — um agente por nó automaticamente.

---

## Passo 2 — Verificar que o agente está rodando

```bash
sudo systemctl status aegis-agent
```

```
● aegis-agent.service - AegisOps Agent
     Loaded: loaded (/etc/systemd/system/aegis-agent.service; enabled)
     Active: active (running) since ...
```

Acompanhe os logs em tempo real:

```bash
journalctl -u aegis-agent -f
```

Saída esperada nos primeiros 30 segundos:

```
aegis-agent: enrollment complete — mTLS certificates installed (expires: 2027-01-01)
aegis-agent: conectado a kong.aegisops.io:443
aegis-agent: heartbeat enviado — org_id=org_...
aegis-agent: collectors iniciados: cpu, memory, disk, network, process, logs
```

Em seguida, abra [dashboard.aegisops.io](https://dashboard.aegisops.io) — seu host deve aparecer no **Service Health Map** em menos de 30 segundos com métricas de CPU, memória e disco já chegando.

---

## Passo 3 — Instrumentar sua aplicação

O agente expõe dois endpoints locais para receber telemetria da sua aplicação:

| Protocolo | Endereço | Uso |
|-----------|----------|-----|
| gRPC (OTLP) | `localhost:4317` | Dodo SDK, OTEL SDK em gRPC |
| HTTP/JSON (OTLP) | `localhost:4318` | OTEL SDK em HTTP, qualquer cliente REST |

Escolha um dos dois caminhos abaixo.

---

### Caminho A — Dodo SDK (Go)

O SDK Go é a integração mais completa, com suporte a eventos customizados de negócio, métricas, health checks e spans manuais.

**Instalar:**

```bash
go get github.com/OppervisionTech/dodo_sdk_go/aegis
```

**Usar:**

```go
package main

import (
    "github.com/OppervisionTech/dodo_sdk_go/aegis"
)

func main() {
    client := aegis.New(aegis.Config{
        ServiceName: "meu-servico",
        Version:     "1.0.0",
        Environment: "production",
        // AgentAddr padrão: localhost:4317
    })
    defer client.Close()

    // Evento de negócio customizado
    client.Event("pedido.criado", aegis.Fields{
        "order_id": "ORD-123",
        "valor":    299.90,
        "moeda":    "BRL",
    })

    // Métricas
    client.Gauge("fila.profundidade", 42, aegis.Labels{"fila": "pedidos"})
    client.Counter("requests.total", 1, aegis.Labels{"status": "200"})
    client.Histogram("latencia_ms", 23.5, aegis.Labels{"endpoint": "/checkout"})

    // Health check de dependências
    client.Health("banco_de_dados", aegis.HealthOK)
    client.HealthWithDetails("api_externa", aegis.HealthDown, aegis.Fields{
        "erro": "timeout após 5s",
    })

    // Span manual com child span
    span := client.StartSpan("processar_pagamento")
    span.SetAttribute("payment_id", "PAY-456")

    dbSpan := span.StartChild("db_insert")
    dbSpan.SetStatus(aegis.SpanOK)
    dbSpan.End()

    span.SetStatus(aegis.SpanOK)
    span.End()
}
```

> **SDKs Python, Node.js, Java e .NET** estão em desenvolvimento. Por enquanto, use o Caminho B com OpenTelemetry para essas linguagens.

---

### Caminho B — OpenTelemetry (qualquer linguagem)

Se você já usa OpenTelemetry ou prefere a abordagem agnóstica a linguagem, basta apontar seu exporter para o agente local.

**Variáveis de ambiente (universal):**

```bash
export OTEL_SERVICE_NAME="meu-servico"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
export OTEL_RESOURCE_ATTRIBUTES="deployment.environment=production,service.version=1.0.0"
```

#### Python

```bash
pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-http
```

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

provider = TracerProvider()
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces"))
)
trace.set_tracer_provider(provider)

tracer = trace.get_tracer("meu-servico")

with tracer.start_as_current_span("processar_pedido") as span:
    span.set_attribute("order_id", "ORD-123")
    # sua lógica aqui
```

Para **Flask** ou **FastAPI**, use a auto-instrumentação:

```bash
pip install opentelemetry-instrumentation-flask
opentelemetry-instrument --traces_exporter otlp python app.py
```

#### Node.js

```bash
npm install @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http
```

```javascript
const { NodeSDK } = require('@opentelemetry/sdk-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');

const sdk = new NodeSDK({
  traceExporter: new OTLPTraceExporter({
    url: 'http://localhost:4318/v1/traces',
  }),
});

sdk.start();
```

#### Java

Baixe o [OpenTelemetry Java Agent](https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/latest) e adicione ao startup da JVM:

```bash
java -javaagent:opentelemetry-javaagent.jar \
  -Dotel.service.name=meu-servico \
  -Dotel.exporter.otlp.endpoint=http://localhost:4318 \
  -jar minha-aplicacao.jar
```

#### .NET

```bash
dotnet add package OpenTelemetry.Exporter.OpenTelemetryProtocol
```

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(b => b
        .AddOtlpExporter(opt => opt.Endpoint = new Uri("http://localhost:4318"))
        .AddAspNetCoreInstrumentation());
```

---

## Passo 4 — Ver os dados no dashboard

1. Acesse [dashboard.aegisops.io](https://dashboard.aegisops.io)
2. **Service Health Map** — todos os hosts com o agente instalado aparecem aqui
3. **Explorar → Métricas** — CPU, memória, disco e métricas customizadas do SDK
4. **Explorar → Traces** — traces da sua aplicação (via SDK ou OTEL)
5. **Explorar → Logs** — logs do sistema e da aplicação coletados automaticamente
6. **Explorar → Eventos** — eventos de negócio enviados via `client.Event()`

---

## Integrações automáticas

O agente detecta e monitora automaticamente os serviços abaixo quando as variáveis de ambiente estão definidas:

```bash
# Adicione ao arquivo de ambiente do systemd: /etc/systemd/system/aegis-agent.service.d/override.conf
# Ou exporte antes de iniciar o agente

DODO_AGENT_POSTGRES_DSN=postgresql://user:senha@localhost:5432/meu_banco
DODO_AGENT_MONGODB_URI=mongodb://localhost:27017
DODO_AGENT_REDIS_URL=redis://localhost:6379
```

Docker é detectado automaticamente via socket (`/var/run/docker.sock`) sem configuração adicional.

---

## Referência rápida

```bash
# Ver logs do agente
journalctl -u aegis-agent -f

# Recarregar configuração sem reiniciar
sudo systemctl reload aegis-agent

# Ver dados em buffer local (quando backend indisponível)
ls -lh /var/lib/aegis/buffer/

# Desinstalar completamente
sudo systemctl stop aegis-agent && sudo systemctl disable aegis-agent
sudo rm -rf /etc/aegis /var/lib/aegis /var/log/aegis /usr/local/bin/aegis-agent
sudo rm /etc/systemd/system/aegis-agent.service && sudo systemctl daemon-reload
```

---

## Próximos passos

- **Alertas**: configure alertas em **Configurações → Alertas** no dashboard
- **SLOs**: defina objetivos de nível de serviço em **SLOs**
- **IA**: o AegisOps detecta anomalias automaticamente e exibe diagnósticos em **Incidentes**
- **Arquitetura completa**: consulte [`ARCHITECTURE.md`](../ARCHITECTURE.md) para entender todos os componentes da plataforma
