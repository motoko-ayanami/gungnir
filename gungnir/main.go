package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	logListUrl        = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
	rootDomains       map[string]bool
	discordWebhookURL string // Variable to store the Discord webhook URL
)

var getByScheme = map[string]func(*url.URL) ([]byte, error){
	"http": readHTTP,
	"https": readHTTP,
	"file": func(u *url.URL) ([]byte, error) {
		return os.ReadFile(u.Path)
	},
}

func init() {
	flag.StringVar(&discordWebhookURL, "webhook", "", "The Discord webhook URL for sending alerts")
}

func readHTTP(u *url.URL) ([]byte, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func readURL(u *url.URL) ([]byte, error) {
	s := u.Scheme
	queryFn, ok := getByScheme[s]
	if !ok {
		return nil, fmt.Errorf("failed to identify suitable scheme for the URL %q", u.String())
	}
	return queryFn(u)
}

type ctLog struct {
	id     string
	name   string
	wsth   *ct.SignedTreeHead
	client *client.LogClient
}

func populateLogs(logListURL string) ([]ctLog, error) {
	u, err := url.Parse(logListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	body, err := readURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to get log list data: %v", err)
	}
	logList, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	usable := logList.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	var logs []ctLog
	for _, operator := range usable.Operators {
		for _, log := range operator.Logs {
			logID := base64.StdEncoding.EncodeToString(log.LogID)
			c, err := createLogClient(log.Key, log.URL)
			if err != nil {
				return nil, fmt.Errorf("failed to create log client: %v", err)
			}
			l := ctLog{
				id:     logID,
				name:   log.Description,
				client: c,
			}
			logs = append(logs, l)
		}
	}
	return logs, nil
}

func createLogClient(key []byte, url string) (*client.LogClient, error) {
	pemPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	})
	opts := jsonclient.Options{PublicKey: string(pemPK), UserAgent: "gungnir-" + uuid.New().String()}
	c, err := client.New(url, http.DefaultClient, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON client: %v", err)
	}
	return c, nil
}

func loadRootDomains(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	rootDomains = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rootDomains[scanner.Text()] = true
	}
	return scanner.Err()
}

func isSubdomain(domain string) bool {
	if _, ok := rootDomains[domain]; ok {
		return true
	}
	parts := strings.Split(domain, ".")
	for i := range parts {
		parentDomain := strings.Join(parts[i:], ".")
		if _, ok := rootDomains[parentDomain]; ok {
			return true
		}
	}
	return false
}

func sendDiscordAlert(message string) {
	if discordWebhookURL == "" {
		log.Println("Discord webhook URL is not set. Skipping alert.")
		return
	}
	payload := map[string]string{"content": message}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal Discord message payload: %v", err)
		return
	}
	resp, err := http.Post(discordWebhookURL, "application/json", bytes.NewReader(payloadBytes))
	if err != nil {
		log.Printf("Failed to send Discord alert: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Discord alert returned non-OK status: %d", resp.StatusCode)
	}
}

func scanLog(ctx context.Context, ctl ctLog, wg *sync.WaitGroup) {
	defer wg.Done()
	var err error
	var start int64
	var end int64
	ticker := time.NewTicker(time.Minute * 60)
	errTicker := time.NewTicker(time.Second * 60)
	for {
		ctl.wsth, err = ctl.client.GetSTH(ctx)
		if err != nil {
			log.Printf("Failed to get initial STH for log %s: %v", ctl.client.BaseURI(), err)
			<-errTicker.C
		} else {
			break
		}
	}
	start = int64(ctl.wsth.TreeSize) - 100
	end = int64(ctl.wsth.TreeSize)
	for {
		<-ticker.C
		entries, err := ctl.client.GetRawEntries(ctx, start, end)
		if err != nil {
			log.Printf("Failed to get ENTRIES for log %s: %v\n start: %d  end : %d", ctl.client.BaseURI(), err, start, end)
			continue
		}
		for _, entry := range entries.Entries {
			index := entry.Index
			rle, err := ct.RawLogEntryFromLeaf(index, &entry)
			if err != nil {
				log.Printf("Failed to get parse entry %d: %v", index, err)
				continue
			}
			switch rle.Leaf.TimestampedEntry.EntryType {
			case ct.X509LogEntryType:
				if rle.X509Cert != nil && isSubdomain(rle.X509Cert.Subject.CommonName) {
					sendDiscordAlert(fmt.Sprintf("New certificate for domain %s observed in CT log", rle.X509Cert.Subject.CommonName))
				}
			case ct.PrecertLogEntryType:
				if rle.Precert != nil && isSubdomain(rle.Precert.TBSCertificate.Subject.CommonName) {
					sendDiscordAlert(fmt.Sprintf("New precertificate for domain %s observed in CT log", rle.Precert.TBSCertificate.Subject.CommonName))
				}
			}
		}
		start = end + 1
		<-ticker.C
		ctl.wsth, err = ctl.client.GetSTH(ctx)
		if err != nil {
			log.Printf("Failed to get new STH for log %s: %v", ctl.client.BaseURI(), err)
			<-errTicker.C
			continue
		}
		end = int64(ctl.wsth.TreeSize)
	}
}

func main() {
	flag.Parse()

	if discordWebhookURL == "" {
		log.Fatal("Discord webhook URL must be provided. Use -webhook flag.")
	}

	var rootList string
	flag.StringVar(&rootList, "r", "", "Path to the list of root domains to filter against")
	if rootList != "" {
		if err := loadRootDomains(rootList); err != nil {
			log.Fatalf("Failed to load root domains: %v", err)
		}
	}

	ctLogs, err := populateLogs(logListUrl)
	if err != nil {
		log.Fatalf("Failed to populate CT logs: %v", err)
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	for _, ctl := range ctLogs {
		wg.Add(1)
		go scanLog(ctx, ctl, &wg)
	}

	wg.Wait()
}
