package signing

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ledgerRecord struct {
	JobID string `json:"jobId"`
	Attempt int `json:"attempt"`
	SnapshotSHA256 string `json:"snapshotSha256"`
	InputSHA256 string `json:"inputSha256"`
	OutputSHA256 string `json:"outputSha256,omitempty"`
	Status string `json:"status"`
	UpdatedAt time.Time `json:"updatedAt"`
	PreviousRecordSHA256 string `json:"previousRecordSha256,omitempty"`
	RecordSHA256 string `json:"recordSha256,omitempty"`
}
type ledger struct {
	mu sync.Mutex
	path string
	records map[string]ledgerRecord
	lastHash string
}
func ledgerKey(job string,attempt int)string{return fmt.Sprintf("%s/%d",job,attempt)}
func openLedger(path string)(*ledger,error){
	if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return nil,err}
	if st,err:=os.Lstat(path);err==nil&&(!st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0){return nil,errors.New("signing audit ledger must be a regular non-symlink file")}else if err!=nil&&!os.IsNotExist(err){return nil,err}
	l:=&ledger{path:path,records:map[string]ledgerRecord{}}
	f,err:=os.OpenFile(path,os.O_CREATE|os.O_RDONLY,0600);if err!=nil{return nil,err}
	defer f.Close()
	scanner:=bufio.NewScanner(f);scanner.Buffer(make([]byte,4096),64*1024)
	for scanner.Scan(){
		var r ledgerRecord
		if err:=json.Unmarshal(scanner.Bytes(),&r);err!=nil{return nil,fmt.Errorf("signing ledger is corrupt: %w",err)}
		if r.JobID==""||r.Attempt<1||r.Status==""||r.RecordSHA256==""||r.PreviousRecordSHA256!=l.lastHash{return nil,errors.New("signing ledger contains an invalid or discontinuous audit record")}
		want:=r.RecordSHA256;r.RecordSHA256=""
		canonical,err:=json.Marshal(r);if err!=nil{return nil,err}
		sum:=sha256.Sum256(canonical);if hex.EncodeToString(sum[:])!=want{return nil,errors.New("signing ledger hash-chain verification failed")}
		r.RecordSHA256=want;l.lastHash=want;l.records[ledgerKey(r.JobID,r.Attempt)]=r
	}
	if err:=scanner.Err();err!=nil{return nil,err}
	return l,nil
}
func(l *ledger)get(job string,attempt int)(ledgerRecord,bool){
	l.mu.Lock();defer l.mu.Unlock();r,ok:=l.records[ledgerKey(job,attempt)];return r,ok
}
func(l *ledger)reserve(r ledgerRecord)error{
	l.mu.Lock();defer l.mu.Unlock()
	key:=ledgerKey(r.JobID,r.Attempt);if _,ok:=l.records[key];ok{return errors.New("job attempt already has a signing ledger record")}
	r.Status="signing";r.UpdatedAt=time.Now().UTC()
	if err:=l.appendLocked(r);err!=nil{return err};r.RecordSHA256=l.lastHash;l.records[key]=r;return nil
}
func(l *ledger)update(r ledgerRecord)error{
	l.mu.Lock();defer l.mu.Unlock()
	key:=ledgerKey(r.JobID,r.Attempt);if _,ok:=l.records[key];!ok{return errors.New("signing ledger reservation is missing")}
	r.UpdatedAt=time.Now().UTC()
	if err:=l.appendLocked(r);err!=nil{return err};r.RecordSHA256=l.lastHash;l.records[key]=r;return nil
}
func(l *ledger)appendLocked(r ledgerRecord)error{
	r.PreviousRecordSHA256=l.lastHash;r.RecordSHA256=""
	canonical,err:=json.Marshal(r);if err!=nil{return err}
	sum:=sha256.Sum256(canonical);r.RecordSHA256=hex.EncodeToString(sum[:])
	b,err:=json.Marshal(r);if err!=nil{return err}
	f,err:=os.OpenFile(l.path,os.O_APPEND|os.O_WRONLY,0600);if err!=nil{return err}
	_,err=f.Write(append(b,'
'));if err==nil{err=f.Sync()}
	closeErr:=f.Close();if err!=nil{return err};if closeErr!=nil{return closeErr}
	l.lastHash=r.RecordSHA256
	return nil
}
