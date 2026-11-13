//go:build integration

package spam

import (
	"testing"
)

func TestEndToEnd_TrainAndScore(t *testing.T) {
	model := NewModel(DefaultFeatureSize)

	// Train on 50 spam and 50 ham messages built from templates.
	spamTemplate := []byte("From: spam-@evil.com\r\nSubject: WINNER Prize Claim\r\n\r\nhttp://evil.com/claim Click here to claim your prize! You won!!!")
	hamTemplate := []byte("From: alice@setjoin.com\r\nSubject: Meeting Agenda\r\nMessage-Id: <msg@setjoin.com>\r\nDate: Mon, 1 Jun 2026\r\nContent-Type: text/plain\r\n\r\nHere is the meeting agenda for next week. Please review and send feedback.")

	for i := 0; i < 50; i++ {
		model.Train(spamTemplate, true)
		model.Train(hamTemplate, false)
	}

	// Fresh examples should be correctly classified.
	testSpam := []byte("From: winner@lottery.com\r\nSubject: CLAIM YOUR PRIZE\r\n\r\nhttp://lottery.com/prize You are a winner! Click here now!")
	testHam := []byte("From: bob@setjoin.com\r\nSubject: Q3 Budget Review\r\nMessage-Id: <test@setjoin.com>\r\nDate: Wed, 4 Jun 2026\r\nContent-Type: text/plain\r\n\r\nPlease review the attached budget for Q3. Comments due Friday.")

	spamScore := model.Score(testSpam)
	hamScore := model.Score(testHam)

	if spamScore < 0.8 {
		t.Errorf("spam score too low: %.4f (expected > 0.8)", spamScore)
	}
	if hamScore > 0.3 {
		t.Errorf("ham score too high: %.4f (expected < 0.3)", hamScore)
	}

	// Persist + restore.
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	model2 := NewModel(DefaultFeatureSize)
	if err := model2.Load(data); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if model.Score(testSpam) != model2.Score(testSpam) {
		t.Error("scores diverge after persist")
	}
}
