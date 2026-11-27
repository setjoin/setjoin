import "@typespec/http";

using TypeSpec.Http;

namespace SetjoinEdge.Common;

@doc("Shared cursor-based pagination query parameters.")
model CursorPaginationQuery {
  @query
  @doc("Opaque cursor returned by the previous page.")
  cursor?: string;

  @query
  @doc("Maximum number of items to return.")
  limit?: int32;
}

@doc("Shared offset-based pagination query parameters.")
model OffsetPaginationQuery {
  @query
  @doc("Maximum number of items to return.")
  limit?: int32;

  @query
  @doc("Zero-based item offset.")
  offset?: int32;
}

@doc("Shared cursor pagination envelope metadata.")
model CursorPageMeta {
  @doc("Cursor to fetch the next page, or null when exhausted.")
  nextCursor?: string | null;

  @doc("True when additional pages follow.")
  hasMore: boolean;
}
