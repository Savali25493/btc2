package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

func h160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

func addrOf(k []byte, comp bool) string {
	pk := secp256k1.PrivKeyFromBytes(k)
	var pub []byte
	if comp {
		pub = pk.PubKey().SerializeCompressed()
	} else {
		pub = pk.PubKey().SerializeUncompressed()
	}
	return b58check(append([]byte{0x00}, h160(pub)...))
}

func wifOf(k []byte) string {
	return b58check(append(append([]byte{0x80}, k...), 0x01))
}

type mt64 struct {
	mt [312]uint64
	i  int
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
		binary.LittleEndian.PutUint64(k[j*8:], y)
	}
	return k
}

func main() {
	in := flag.String("in", "", "tsv file")
	col := flag.Int("col", 1, "balance column (0-based)")
	capN := flag.Int("cap", 100000, "max targets")
	prefix := flag.String("prefix", "0x000", "required address prefix (empty = none)")
	out := flag.String("out", "found.txt", "results file")
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
	var mu sync.Mutex

	f, err := os.Open(*in)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lines := make(chan string, 200000)
	var wg sync.WaitGroup
	for i := 0; i < *procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range lines {
				if len(targets) >= *capN {
					return
				}
				p := strings.Split(l, "\t")
				if len(p) <= *col {
					continue
				}
				a := p[0]
				if *prefix != "" && !strings.HasPrefix(strings.ToLower(a), *prefix) {
					continue
				}
				if strings.TrimSpace(p[*col]) == "" || strings.TrimSpace(p[*col]) == "0" {
					continue
				}
				mu.Lock()
				if len(targets) < *capN {
					targets[a] = struct{}{}
				}
				mu.Unlock()
			}
		}()
	}
	start := time.Now()
	for sc.Scan() {
		if len(targets) >= *capN {
			break
		}
		lines <- sc.Text()
	}
	close(lines)
	wg.Wait()
	f.Close()
	fmt.Printf("targets: %d (%.0fs)\n", len(targets), time.Since(start).Seconds())
	if len(targets) == 0 {
		return
	}

	of, _ := os.Create(*out)
	defer of.Close()
	var hits int64
	var foundMu sync.Mutex

	const chunk = 200000
	seed := make(chan uint64, 64)
	var w2 sync.WaitGroup
	t0 := time.Now()
	var done int64

	for i := 0; i < *procs; i++ {
		w2.Add(1)
		go func() {
			defer w2.Done()
			for s := range seed {
				for j := uint64(0); j < chunk && s+j < total; j++ {
					k := profKey(s + j)
					a := addrOf(k, true)
					if _, ok := targets[a]; ok {
						line := fmt.Sprintf("%d\t%s\t%s\t%s\n", s+j, a, hex.EncodeToString(k), wifOf(k))
						foundMu.Lock()
						of.WriteString(line)
						fmt.Print("HIT ", line)
						atomic.AddInt64(&hits, 1)
						foundMu.Unlock()
					}
				}
				n := atomic.AddInt64(&done, chunk)
				if n%200000 == 0 {
					el := time.Since(t0).Seconds()
					rate := float64(n) / el
					fmt.Printf("%d seeds | %.0f/s | eta %.0f min\n", n, rate, (float64(total)-float64(n))/rate/60)
				}
			}
		}()
	}
	for s := from; s < total; s += chunk {
		seed <- s
	}
	close(seed)
	w2.Wait()
	fmt.Printf("done. hits: %d\n", hits)
}

const b58alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	zero := big.NewInt(0)
	base := big.NewInt(58)
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		out = append(out, b58alpha[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func b58check(payload []byte) string {
	h := sha256.Sum256(payload)
	h2 := sha256.Sum256(h[:])
	return b58encode(append(payload, h2[:4]...))
}