import "@typespec/http";
import "./common/problem.tsp";
import "./common/pagination.tsp";
import "./modules/health.tsp";
import "./modules/rules.tsp";
import "./modules/delivery.tsp";
import "./modules/offline.tsp";

using TypeSpec.Http;

@service(#{ title: "Setjoin Edge API" })
@doc("Canonical schema-first HTTP edge contract for Setjoin non-JMAP/non-DAV APIs (OpenAPI 3.1).")
namespace SetjoinEdge;
