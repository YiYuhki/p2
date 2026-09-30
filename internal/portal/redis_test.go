package portal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisTicketsAndCodes(t *testing.T) {
	addr := os.Getenv("SECMAIL_TEST_REDIS")
	if addr == "" {
		t.Skip("SECMAIL_TEST_REDIS not set")
	}
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()
	prefix := "test-" + uuid.NewString()[:8]

	tk := NewRedisTickets(rdb, prefix)
	ticket, err := tk.Issue(ctx, "att-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := tk.Redeem(ctx, ticket); err != nil || id != "att-1" {
		t.Fatalf("redeem: %q %v", id, err)
	}
	if _, err := tk.Redeem(ctx, ticket); err != ErrTicketInvalid {
		t.Fatalf("ticket reuse: %v", err)
	}

	codes := NewRedisCodes(rdb, prefix)
	email := "u@example.com"
	if ok, err := codes.Put(ctx, email, "111111", time.Minute, time.Minute); !ok || err != nil {
		t.Fatalf("put: %v %v", ok, err)
	}
	if ok, _ := codes.Put(ctx, email, "222222", time.Minute, time.Minute); ok {
		t.Fatal("resend throttle not applied")
	}
	if ok, _ := codes.Check(ctx, email, "000000", 3); ok {
		t.Fatal("wrong code accepted")
	}
	if ok, _ := codes.Check(ctx, email, "111111", 3); !ok {
		t.Fatal("right code rejected")
	}
	if ok, _ := codes.Check(ctx, email, "111111", 3); ok {
		t.Fatal("code reused")
	}

	email2 := "v@example.com"
	codes.Put(ctx, email2, "333333", time.Minute, time.Minute)
	for i := 0; i < 3; i++ {
		codes.Check(ctx, email2, "000000", 3)
	}
	if ok, _ := codes.Check(ctx, email2, "333333", 3); ok {
		t.Fatal("code survived max attempts")
	}
	rdb.Del(ctx, prefix+":otp:"+hashKey(email), prefix+":otp:rl:"+hashKey(email),
		prefix+":otp:"+hashKey(email2), prefix+":otp:rl:"+hashKey(email2))
}
