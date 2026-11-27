import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Health;

@doc("Redacted aggregate health verdict.")
union HealthVerdict {
  ok: "ok",
  warn: "warn",
  error: "error",
}

@doc("Exact readiness verdict literal.")
union ReadyVerdict {
  ok: "ok",
}

@doc("Public /health JSON verdict payload.")
model HealthStatus {
  status: HealthVerdict;
}

@doc("Public /ready JSON payload.")
model ReadyStatus {
  status: ReadyVerdict;
}

model HealthOkResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: HealthStatus;
}

model HealthDegradedResponse {
  @statusCode statusCode: 503;
  @header("content-type") contentType: "application/json";
  @body body: HealthStatus;
}

model PlainTextOkResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "text/plain";
  @body body: string;
}

model PlainTextErrorResponse {
  @statusCode statusCode: 500;
  @header("content-type") contentType: "text/plain";
  @body body: string;
}

model PlainTextUnavailableResponse {
  @statusCode statusCode: 503;
  @header("content-type") contentType: "text/plain";
  @body body: string;
}

model ReadyOkResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: ReadyStatus;
}

@tag("Health")
interface HealthOperations {
  @get
  @route("/health")
  @summary("Aggregate public health verdict")
  getHealth():
    | HealthOkResponse
    | TooManyRequestsProblem
    | PlainTextErrorResponse
    | HealthDegradedResponse;

  @get
  @route("/healthz")
  @summary("Process liveness probe")
  getHealthz(): PlainTextOkResponse;

  @get
  @route("/_gateway/healthz")
  @summary("Gateway-local liveness probe")
  getGatewayHealthz(): PlainTextOkResponse;

  @get
  @route("/ready")
  @summary("Database readiness probe")
  getReady(): ReadyOkResponse | TooManyRequestsProblem | PlainTextUnavailableResponse;
}
