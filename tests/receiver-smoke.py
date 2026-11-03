#!/usr/bin/env python3
"""Cross-repository smoke: actual SDKs -> actual agent -> synthetic upstream.

Build agent with `cargo build --no-default-features --features otel` for a
portable mock platform, or pass a supported-platform binary. No real backend,
credentials or tenant data are used. Run after unit tests with explicit paths.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--python-sdk', required=True)
parser.add_argument('--go-client', required=True)
args = parser.parse_args()
sys.path.insert(0, str(Path(args.python_sdk).resolve()))
import grpc
from aegis.client import Client
from aegis.config import Config
from dodo.proto.v1 import envelope_pb2 as pb, ingestor_service_pb2_grpc as svc, metric_pb2 as metrics


class Upstream(svc.IngestorServiceServicer):
    envelopes = []
    available = True
    def SubmitBatch(self, request, context):
        if not self.available:
            context.abort(grpc.StatusCode.UNAVAILABLE, 'synthetic outage')
        self.envelopes.extend(request.envelopes)
        return pb.SubmitBatchResponse(accepted=len(request.envelopes))

upstream = Upstream()
# Spawn the Rust process before creating any gRPC background threads. Forking
# a Python gRPC server can hang in at-fork handlers on macOS.
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
server = None
with tempfile.TemporaryDirectory(prefix='dodo-receiver-smoke-') as tmp:
    root = Path(tmp)
    config = root / 'agent.yaml'
    config.write_text(f'''endpoint:
  address: "127.0.0.1:{port}"
  timeout_ms: 1000
  retry_max: 0
tls:
  enabled: false
buffer:
  path: "{root}/buffer"
  flush_interval_ms: 100
agent_id_path: "{root}/agent_id"
enrollment_endpoint: ""
collectors:
  - name: otel
    enabled: true
    interval_seconds: 1
''')
    env = {**os.environ, 'AEGIS_CONFIG': str(config)}
    env.pop('DODO_ENDPOINT', None)
    env.pop('DODO_ENROLLMENT_ENDPOINT', None)
    env.pop('DODO_API_KEY', None)
    with (root / 'agent.log').open('w+') as log:
        process = subprocess.Popen([str(Path(args.binary).resolve())], env=env, stdout=log, stderr=log, close_fds=False)
        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        svc.add_IngestorServiceServicer_to_server(upstream, server)
        assert server.add_insecure_port(f'127.0.0.1:{port}') == port
        server.start()
        try:
            deadline = time.monotonic() + 60
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(f'agent exited: {log.read()}')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:4318/readyz', timeout=.5) as response:
                        assert response.status == 200
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        log.flush(); log.seek(0); print(log.read()[-10000:]); raise
                    time.sleep(.1)
            probe_channel = grpc.insecure_channel('127.0.0.1:4317')
            try:
                print('EMPTY_PROBE', svc.IngestorServiceStub(probe_channel).SubmitBatch(pb.SubmitBatchRequest(), timeout=2))
            except grpc.RpcError as error:
                print('GRPC_PROBE_FAILURE', error.code(), error.details())
                log.flush(); log.seek(0); print(log.read())
                raise
            finally:
                probe_channel.close()
            for protocol in ('grpc', 'http'):
                client = Client(Config(service_name='python-receiver-smoke', protocol=protocol,
                    capture_logs=False, runtime_metrics=False, flush_interval=60))
                client.gauge('smoke.python.gauge', 42)
                client.counter('smoke.python.counter', 1)
                client.event('smoke.python.event', {'synthetic': True})
                client.health('smoke.python.health', 'ok')
                with client.span('smoke.python.span'): pass
                client.close()
                assert client.stats().envelopes_sent == 5, client.stats()
                assert client.stats().envelopes_dropped == 0, client.stats()
                subprocess.run([str(Path(args.go_client).resolve()), protocol], check=True, timeout=30, close_fds=False)
            # Forged SDK identity and privileged signals never cross the boundary.
            channel = grpc.insecure_channel('127.0.0.1:4317')
            stub = svc.IngestorServiceStub(channel)
            reply = stub.SubmitBatch(pb.SubmitBatchRequest(envelopes=[
                pb.AgentEnvelope(agent_id='forged', hostname='forged', signal_type=6,
                    timestamp_unix_ns=time.time_ns(), compression=1, payload=b'not a heartbeat')]), timeout=2)
            assert (reply.accepted, reply.rejected) == (0, 1)
            channel.close()
            deadline = time.monotonic() + 10
            while len([e for e in upstream.envelopes if e.signal_type in (3, 8)]) < 12:
                assert time.monotonic() < deadline, f'missing upstream signals: {len(upstream.envelopes)}'
                time.sleep(.1)
            identity = (root / 'agent_id').read_text().strip()
            assert all(e.agent_id == identity and e.agent_id != 'forged' and e.compression == 1 for e in upstream.envelopes)
            assert {1, 3, 8}.issubset({e.signal_type for e in upstream.envelopes})
            def replay_received(name):
                return any(e.signal_type == 1 and metrics.MetricPayload.FromString(e.payload).name == name for e in upstream.envelopes)
            def wait_for(predicate, description, seconds=15):
                deadline = time.monotonic() + seconds
                while not predicate():
                    assert time.monotonic() < deadline, description
                    time.sleep(.1)
            def enqueue_metric(name):
                client = Client(Config(service_name='replay-smoke', capture_logs=False, runtime_metrics=False,flush_interval=60))
                client.gauge(name, 1); client.close()
                assert client.stats().envelopes_sent == 1
            upstream.available = False
            enqueue_metric('smoke.replay.without_restart')
            wait_for(lambda: list((root/'buffer').rglob('*.buf')), 'no durable buffer during outage')
            upstream.available = True
            wait_for(lambda: replay_received('smoke.replay.without_restart'), 'periodic replay did not recover')
            wait_for(lambda: not list((root/'buffer').rglob('*.buf')), 'acknowledged records not removed')
            upstream.available = False
            enqueue_metric('smoke.replay.after_restart')
            wait_for(lambda: list((root/'buffer').rglob('*.buf')), 'restart fixture not buffered')
            process.send_signal(signal.SIGTERM); process.wait(timeout=15)
            upstream.available = True
            process = subprocess.Popen([str(Path(args.binary).resolve())], env=env, stdout=log, stderr=log, close_fds=False)
            wait_for(lambda: replay_received('smoke.replay.after_restart'), 'durable restart replay failed', 60)
            assert (root/'agent_id').read_text().strip() == identity
            assert all(e.agent_id == identity and e.compression == 1 for e in upstream.envelopes)
            print('SDK_AGENT_RECEIVER_SMOKE_OK: Python+Go gRPC/HTTP, identity, outage recovery and durable restart replay')
        finally:
            process.send_signal(signal.SIGTERM)
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
server.stop(0).wait()
