package signing

import (
	"bufio"
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
}
type ledger struct {
	mu sync.Mutex
	path string
	records map[string]ledgerRecord
}
func ledgerKey(job string,attempt int)string{return fmt.Sprintf("%s/%d",job,attempt)}
func openLedger(path string)(*ledger,error){
	if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return nil,err}
	l:=&ledger{path:path,records:map[string]ledgerRecord{}}
	f,err:=os.OpenFile(path,os.O_CREATE|os.O_RDONLY,0600);if err!=nil{return nil,err}
	defer f.Close()
	scanner:=bufio.NewScanner(f);scanner.Buffer(make([]byte,4096),64*1024)
	for scanner.Scan(){var r ledgerRecord;if err:=json.Unmarshal(scanner.Bytes(),&r);err!=nil{return nil,fmt.Errorf("signing ledger is corrupt: %w",err)};if r.JobID==""||r.Attempt<1||r.Status==""{return nil,errors.New("signing ledger contains an invalid record")};l.records[ledgerKey(r.JobID,r.Attempt)]=r}
	if err:=scanner.Err();err!=nil{return nil,err}
	return l,nil
}
func(l *ledger) get(job string,attempt int)(ledgerRecord,bool){
	l.mu.Lock();defer l.mu.Unlock();r,ok:=l.records[ledgerKey(job,attempt)];return r,ok
}
func(l *ledger) reserve(r ledgerRecord)error{
	l.mu.Lock();defer l.mu.Unlock()
	key:=ledgerKey(r.JobID,r.Attempt);if _,ok:=l.records[key];ok{return errors.New("job attempt already has a signing ledger record")}
	r.Status="signing";r.UpdatedAt=time.Now().UTC()
	if err:=l.appendLocked(r);err!=nil{return err};l.records[key]=r;return nil
}
func(l *ledger) update(r ledgerRecord)error{
	l.mu.Lock();defer l.mu.Unlock()
	key:=ledgerKey(r.JobID,r.Attempt);if _,ok:=l.records[key];!ok{return errors.New("signing ledger reservation is missing")}
	r.UpdatedAt=time.Now().UTC()
	if err:=l.appendLocked(r);err!=nil{return err};l.records[key]=r;return nil
}
func(l *ledger) appendLocked(r ledgerRecord)error{
	f,err:=os.OpenFile(l.path,os.O_APPEND|os.O_WRONLY,0600);if err!=nil{return err}
	b,err:=json.Marshal(r);if err==nil{_,err=f.Write(append(b,'
'))}
	if err==nil{err=f.Sync()}
	closeErr:=f.Close();if err!=nil{return err};return closeErr
}
