package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

func ethAddr(k []byte) string {
	pub := secp256k1.PrivKeyFromBytes(k).PubKey().SerializeUncompressed()[1:]
	h := sha3.NewLegacyKeccak256()
	h.Write(pub)
	return hex.EncodeToString(h.Sum(nil)[12:])
}

type mt64 struct {
	mt [312]uint64
	i  int
}

func putLE(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func profKey(seed uint64) []byte {
	m := &mt64{i: 312}
	m.mt[0] = seed
	for j := 1; j < 312; j++ {
		m.mt[j] = 6364136223846793005*(m.mt[j-1]^(m.mt[j-1]>>62)) + uint64(j)
	}
	for j := 0; j < 312; j++ {
		x := (m.mt[j] & 0xFFFFFFFF80000000) | (m.mt[(j+1)%312] & 0x7FFFFFFF)
		var v uint64
		if x&1 != 0 {
			v = 0xB5026F5AA96619E9
		}
		m.mt[j] = m.mt[(j+156)%312] ^ (x >> 1) ^ v
	}
	k := make([]byte, 32)
	for j := 0; j < 4; j++ {
		y := m.mt[j]
		y ^= (y >> 29) & 0x5555555555555555
		y ^= (y << 17) & 0x71D67FFFEDA60000
		y ^= (y << 37) & 0xFFF7EEE000000000
		y ^= y >> 43
		putLE(k[j*8:], y)
	}
	return k
}

func main() {
	in := flag.String("in", "", "targets file")
	col := flag.Int("col", 0, "address column")
	capN := flag.Int("cap", 50000, "max targets")
	prefix := flag.String("prefix", "000", "required prefix")
	out := flag.String("out", "found_eth.txt", "results file")
	procs := flag.Int("procs", runtime.NumCPU(), "workers")
	startN := flag.Uint64("start", 0, "seed start")
	endN := flag.Uint64("end", 0, "seed end (0 = 2^32)")
	flag.Parse()

	total := *endN
	if total == 0 {
		total = uint64(1) << 32
	}
	from := *startN
	if from > total {
		from = total
	}

	targets := make(map[string]struct{}, *capN)
	f, err := os.Open(*in)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() && n < *capN {
		p := strings.Split(sc.Text(), "\t")
		if len(p) <= *col {
			continue
		}
		a := strings.ToLower(strings.TrimSpace(p[*col]))
		a = strings.TrimPrefix(a, "0x")
		if *prefix != "" && !strings.HasPrefix(a, *prefix) {
			continue
		}
		targets[a] = struct{}{}
		n++
	}
	f.Close()
	fmt.Printf("targets: %d\n", len(targets))
	if len(targets) == 0 {
		return
	}

	of, _ := os.Create(*out)
	defer of.Close()
	var hits int64
	var mu sync.Mutex

	const chunk = 200000
	seed := make(chan uint64, 64)
	var wg sync.WaitGroup
	t0 := time.Now()
	var done int64

	for i := 0; i < *procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range seed {
				for j := uint64(0); j < chunk && s+j < total; j++ {
					k := profKey(s + j)
					a := ethAddr(k)
					if _, ok := targets[a]; ok {
						line := fmt.Sprintf("%d\t0x%s\t%s\n", s+j, a, hex.EncodeToString(k))
						mu.Lock()
						of.WriteString(line)
						fmt.Print("HIT ", line)
						atomic.AddInt64(&hits, 1)
						mu.Unlock()
					}
				}
				d := atomic.AddInt64(&done, chunk)
				if d%200000 == 0 {
					el := time.Since(t0).Seconds()
					rate := float64(d) / el
					fmt.Printf("%d seeds | %.0f/s | eta %.0f min\n", d, rate, (float64(total)-float64(d))/rate/60)
				}
			}
		}()
	}
	for s := from; s < total; s += chunk {
		seed <- s
	}
	close(seed)
	wg.Wait()
	fmt.Printf("done. hits: %d\n", hits)
}