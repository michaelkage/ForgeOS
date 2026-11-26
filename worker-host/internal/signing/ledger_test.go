package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerReservesAttemptsOnceAndReloadsAppendOnlyRecords(t *testing.T){
	path:=filepath.Join(t.TempDir(),"audit","ledger.jsonl")
	l,err:=openLedger(path);if err!=nil{t.Fatal(err)}
	r:=ledgerRecord{JobID:"123e4567-e89b-42d3-a456-426614174000",Attempt:1,SnapshotSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",InputSHA256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if err:=l.reserve(r);err!=nil{t.Fatal(err)}
	if err:=l.reserve(r);err==nil{t.Fatal("expected duplicate attempt reservation rejection")}
	r.Status="complete";r.OutputSHA256="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err:=l.update(r);err!=nil{t.Fatal(err)}
	reloaded,err:=openLedger(path);if err!=nil{t.Fatal(err)}
	got,ok:=reloaded.get(r.JobID,r.Attempt);if !ok||got.Status!="complete"||got.OutputSHA256!=r.OutputSHA256{t.Fatalf("unexpected reloaded ledger record: %#v",got)}
	info,err:=os.Stat(path);if err!=nil{t.Fatal(err)};if info.Mode().Perm()&0077!=0{t.Fatalf("ledger permissions are too broad: %o",info.Mode().Perm())}
}
