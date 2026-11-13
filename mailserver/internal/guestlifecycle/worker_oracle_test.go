//go:build gofree_record

package guestlifecycle

// Recording hook only: production control flow remains frozen. Rust's fixture
// owns seeding, HTTP SFU capture, committed-row observation and teardown.
import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type oracleRooms struct{ client *lksdk.RoomServiceClient }

func (r oracleRooms) RemoveParticipant(ctx context.Context, room, identity string) error {
	_, err := r.client.RemoveParticipant(ctx, &livekit.RoomParticipantIdentity{Room: room, Identity: identity})
	return err
}
func TestRecordGuestLifecycleTick(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, "2222222222222222222222222222222222222222222222222222222222222222")
	var rooms ParticipantRemover
	if endpoint := os.Getenv("GOFREE_GUEST_SFU_URL"); endpoint != "" {
		rooms = oracleRooms{lksdk.NewRoomServiceClient(endpoint, "test-key", "test-secret")}
	}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, rooms, testsupport.TestLogger())
	switch os.Getenv("GOFREE_GUEST_WORKER_MODE") {
	case "expire":
		worker.expireDue(t.Context())
	case "drain":
		id, err := strconv.ParseInt(os.Getenv("GOFREE_GUEST_WORKER_UID"), 10, 64)
		if err != nil || id <= 0 {
			t.Fatal("positive owned fixture user required")
		}
		if err := worker.DrainUser(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("explicit recorder mode required")
	}
}
