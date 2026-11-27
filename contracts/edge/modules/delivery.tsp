import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Delivery;

@doc("Inbound direction discriminator.")
union InboundDirection {
  inbound: "inbound",
}

@doc("Outbound direction discriminator.")
union OutboundDirection {
  outbound: "outbound",
}

@doc("Direction of a traced message.")
union TraceDirection {
  inbound: "inbound",
  outbound: "outbound",
}

@doc("Latest per-recipient outbound delivery status.")
union RecipientStatus {
  delivered: "delivered",
  deferred: "deferred",
  bounced: "bounced",
  queued: "queued",
}

@doc("A parsed Received header hop for an inbound message trace.")
model TraceHop {
  index: int32;
  fromHost?: string;
  byHost?: string;
  withProtocol?: string;
  ip?: string;
  rdns?: string;
  timestamp: string | null;
  delayMs: int64 | null;
  tlsActive: boolean;
  isOurInfra: boolean;
  parseOk: boolean;
  rawLine?: string;
}

@doc("Authentication mechanism verification outcome.")
model TraceAuthResult {
  result: string;
  domain?: string;
  evidence?: string;
}

@doc("Aggregate SPF/DKIM/DMARC/ARC verification outcomes.")
model TraceAuthResults {
  spf?: TraceAuthResult;
  dkim?: TraceAuthResult;
  dmarc?: TraceAuthResult;
  arc?: TraceAuthResult;
}

@doc("One append-only outbound SMTP delivery attempt.")
model DeliveryAttempt {
  n: int32;
  at: string | null;
  mxHost: string | null;
  smtpCode: int32 | null;
  smtpText: string | null;
  outcome: string;
  tls: boolean;
}

@doc("Latest per-recipient outbound delivery state.")
model DeliveryRecipient {
  email: string;
  status: RecipientStatus;
  mxHost: string | null;
  deliveredAt: string | null;
  nextAttemptAt: string | null;
  lastSmtpCode: int32 | null;
  lastSmtpText: string | null;
  attempts: DeliveryAttempt[];
}

@doc("Reference to the raw RFC 5322 message download.")
model RawMessageRef {
  url: string;
  sizeBytes: int64;
}

@doc("Inbound message trace containing parsed Received header hops.")
model InboundDeliveryTrace {
  direction: InboundDirection;
  hopCount: int32;
  totalTransitMs: int64 | null;
  slowestHopIndex: int32 | null;
  hops: TraceHop[];
  truncated?: boolean;
  auth?: TraceAuthResults;
  raw?: RawMessageRef;
}

@doc("Outbound message trace containing per-recipient SMTP delivery state.")
model OutboundDeliveryTrace {
  direction: OutboundDirection;
  auth?: TraceAuthResults;
  raw?: RawMessageRef;
  overallStatus: string;
  recipients: DeliveryRecipient[];
}

@doc("Discriminated inbound hop trace or outbound per-recipient delivery trace for an owned message.")
union MessageTrace {
  inbound: InboundDeliveryTrace,
  outbound: OutboundDeliveryTrace,
}

model MessageTraceResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: MessageTrace;
}

@tag("Delivery")
interface DeliveryOperations {
  @get
  @route("/api/messages/{emailId}/trace")
  @summary("Fetch inbound hop trace or outbound delivery status for an owned message")
  getMessageTrace(
    @path @pattern("^[+-]?[0-9]+$") emailId: string,
  ):
    | MessageTraceResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | NotFoundTextResponse
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;
}
