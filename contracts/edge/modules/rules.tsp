import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Rules;

@doc("Where a mail rule executes.")
union RunOn {
  server: "server",
  client: "client",
  both: "both",
}

@doc("How far back a retroactive rule sweep reaches.")
union RetroWindow {
  days90: "90d",
  year1: "1y",
  all: "all",
}

@doc("Accepted retroactive sweep window wire value; empty string defaults server-side to 90d.")
union RetroWindowInput {
  days90: "90d",
  year1: "1y",
  all: "all",
  defaultWindow: "",
}

@doc("Execution status of a retroactive rule sweep job.")
union ApplyJobStatus {
  pending: "pending",
  processing: "processing",
  done: "done",
  failed: "failed",
}

@doc("A rule-engine condition matching message attributes.")
model RuleCondition {
  field: string;
  `op`: string;
  value: string;
}

@doc("A rule-engine action executed when conditions match.")
model RuleAction {
  type: string;
  params?: Record<string>;
}

@doc("A user-owned personal mail rule.")
model UserRule {
  id: int64;
  mailboxId: int64;
  name: string;
  enabled: boolean;
  priority: int32;
  runOn: RunOn;
  isTransportRule: boolean;
  conditions: RuleCondition[] | null;
  actions: RuleAction[] | null;
  stopProcessing: boolean;
  createdAt: string;
  updatedAt: string;
}

@doc("Payload to create a personal mail rule.")
model RuleInput {
  name: string;
  enabled: boolean;
  priority: int32;
  runOn: RunOn;
  conditions: RuleCondition[] | null;
  actions: RuleAction[] | null;
  stopProcessing: boolean;
}

@doc("Payload to update a personal mail rule (partial fields accepted server-side).")
model RuleUpdateInput {
  name?: string;
  enabled?: boolean;
  priority?: int32;
  runOn?: RunOn;
  conditions?: RuleCondition[] | null;
  actions?: RuleAction[] | null;
  stopProcessing?: boolean;
}

@doc("Identifier of a newly created rule.")
model CreateRuleResponse {
  id: int64;
}

@doc("Request body to enqueue a retroactive rule sweep (omitted or empty window defaults to 90d).")
model ApplyRetroRequest {
  window?: RetroWindowInput;
}

@doc("Accepted retroactive rule sweep handle.")
model ApplyRetroResult {
  actionId: string;
  status: string;
}

@doc("Progress and outcome of a retroactive rule sweep.")
model ApplyStatus {
  status: ApplyJobStatus;
  processed?: int64;
  truncated?: boolean;
}

model RulesListResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: UserRule[];
}

model RuleCreatedResponse {
  @statusCode statusCode: 201;
  @header("content-type") contentType: "application/json";
  @body body: CreateRuleResponse;
}

model RuleNoContentResponse {
  @statusCode statusCode: 204;
}

model ApplyAcceptedResponse {
  @statusCode statusCode: 202;
  @header("content-type") contentType: "application/json";
  @body body: ApplyRetroResult;
}

model ApplyStatusResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: ApplyStatus;
}

@tag("Rules")
interface RulesOperations {
  @get
  @route("/api/settings/rules-list")
  @summary("List personal mail rules for the authenticated user")
  listRules():
    | RulesListResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @post
  @route("/api/settings/rules")
  @summary("Create a personal mail rule")
  createRule(
    @body body: RuleInput,
  ):
    | RuleCreatedResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @put
  @route("/api/settings/rules/{id}")
  @summary("Update a personal mail rule")
  updateRule(
    @path id: int64,
    @body body: RuleUpdateInput,
  ):
    | RuleNoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @delete
  @route("/api/settings/rules/{id}")
  @summary("Delete a personal mail rule")
  deleteRule(
    @path id: int64,
  ):
    | RuleNoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @post
  @route("/api/settings/rules/{id}/apply")
  @summary("Enqueue retroactive rule sweep against existing mail")
  applyRuleRetro(
    @path id: int64,
    @body body: ApplyRetroRequest,
  ):
    | ApplyAcceptedResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @get
  @route("/api/settings/rules/apply/{actionId}")
  @summary("Poll retroactive rule sweep status (unknown or invalid UUID lookup errors map to 404)")
  getApplyStatus(
    @path @format("uuid") actionId: string,
  ):
    | ApplyStatusResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | TooManyRequestsProblem
    | ServiceUnavailableProblem;
}
