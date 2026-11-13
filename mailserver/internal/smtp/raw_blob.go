package smtp

import (
	"bytes"
	"context"

	"github.com/minio/minio-go/v7"
)

// rawBlobPutter adapts a MinIO client to the putBlob seam the MTA and MSA
// servers share: store raw RFC 5322 wire bytes under the content-addressed key
// BEFORE the row that references them is written (messages.raw_ref /
// outbound_queue.raw_ref). Pre-fix, submission.go and inbound.go referenced
// "blobs/<sha>" / "inbound/<sha>" keys they never stored, so every consumer of
// those refs (outbound drain, .eml download, spam trainer, ediscovery export)
// read nonexistent objects.
func rawBlobPutter(mc *minio.Client, bucket string) func(context.Context, string, []byte) error {
	return func(ctx context.Context, key string, data []byte) error {
		_, err := mc.PutObject(ctx, bucket, key, bytes.NewReader(data), int64(len(data)),
			minio.PutObjectOptions{ContentType: "message/rfc822"})
		return err
	}
}

// SetBlobStore wires the object store the MSA stores submitted raw messages
// into. nil-safe by omission: when unset (tests without S3), the raw blob is
// not stored — main.go always wires it.
func (s *SubmissionServer) SetBlobStore(mc *minio.Client, bucket string) {
	s.putBlob = rawBlobPutter(mc, bucket)
}

// SetBlobStore wires the object store the MTA stores inbound raw messages into.
func (s *InboundServer) SetBlobStore(mc *minio.Client, bucket string) {
	s.putBlob = rawBlobPutter(mc, bucket)
}
