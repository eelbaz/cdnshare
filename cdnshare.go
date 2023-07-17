package main

import (
	"context"
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	_ "github.com/go-sql-driver/mysql"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/likexian/whois"
)

const IPINFO_TOKEN = "__YOUR_IPINFO_TOKEN_HERE"

type Config struct {
	Database struct {
		Host         string `json:"host"`
		Port         string `json:"port"`
		Database     string `json:"database"`
		User         string `json:"user"`
		Password     string `json:"password"`
		MaxOpenConns int    `json:"maxOpenConns"`
		MaxIdleConns int    `json:"maxIdleConns"`
	} `json:"database"`

	Accounts []Account `json:"accounts"`
}

type Account struct {
	Name             string            `json:"name"`
	Unit             string            `json:"unit"`
	ID               string            `json:"id"`
	URLs             map[string]string `json:"urls"`
	MediaTypeFilters []string          `json:"mediaTypeFilters"`
	SleepDuration    int64             `json:"sleepDuration"`
	DBTableName      string            `json:"db_table_name"`
}

type CdnShareData struct {
	Timestamp          time.Time
	CdnIp              string
	CustomerHostname   string
	CdnOrgName         string
	CustomerStreamType string
	AccountName        string
	AccountUnit        string
	AccountID          string
	ParsedWhois        string
}

type WhoisCacheData struct {
	Timestamp   time.Time
	CdnOrgName  string
	ParsedWhois string
}

var cdnOrgNameMappings = []PrettyNameMapping{
	{
		Pattern:    "Eweka",
		PrettyName: "StackPath LLC.",
	},
	{
		Pattern:    "Amazon",
		PrettyName: "Amazon, Inc.",
	},
	{
		Pattern:    "Fastly",
		PrettyName: "Fastly, Inc.",
	},
	{
		Pattern:    "Akamai",
		PrettyName: "Akamai, Inc.",
	},
	{
		Pattern:    "Stack",
		PrettyName: "StackPath LLC.",
	},

	// Add more mappings as needed
}

var config Config
var db *sql.DB
var whoisCache = make(map[string]WhoisCacheData)
var cacheFile = "whois_cache.gob"

func main() {
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalln("Error reading config file:", err)
	}

	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatalln("Error unmarshalling JSON:", err)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", config.Database.User, config.Database.Password, config.Database.Host, config.Database.Port, config.Database.Database)

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalln("Error opening database:", err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalln("Error closing database:", err)
		}
	}()

	err = loadCache()
	if err != nil {
		log.Fatalln("Error loading cache:", err)
	}

	var wg sync.WaitGroup
	for _, account := range config.Accounts {
		wg.Add(1)
		go func(account Account) {
			defer wg.Done()
			for streamType, url := range account.URLs {
				collectStreamingURLs(account, url, streamType)
			}
		}(account)
	}
	wg.Wait()

	err = saveCache()
	if err != nil {
		log.Fatalln("Error saving cache:", err)
	}
}

func collectStreamingURLs(account Account, url string, streamType string) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			listenForNetworkEvents(ctx, account, streamType)
			return nil
		}),
		chromedp.Navigate(url),
		chromedp.Sleep(time.Duration(account.SleepDuration)*time.Second),
	)

	if err != nil {
		log.Printf("Failed to navigate to URL %s: %v\n", url, err)
	}
}

func listenForNetworkEvents(ctx context.Context, account Account, streamType string) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			processRequest(ev, account, streamType)
		}
	})
}
func processRequest(ev *network.EventRequestWillBeSent, account Account, streamType string) {
	for _, filter := range account.MediaTypeFilters {
		if strings.Contains(ev.Request.URL, filter) {
			processFilteredRequest(ev.Request.URL, account, streamType)
		}
	}
}

func processFilteredRequest(url string, account Account, streamType string) {
	data, err := who(url)
	if err != nil {
		log.Println("Error getting WHOIS data:", err)
		return
	}

	data.CustomerStreamType = streamType
	data.AccountName = account.Name
	data.AccountUnit = account.Unit
	data.AccountID = account.ID

	err = saveData(account, data)
	if err != nil {
		log.Println("Error saving data:", err)
		return
	}

	time.Sleep(time.Duration(account.SleepDuration) * time.Second)
}

func who(u string) (CdnShareData, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return CdnShareData{}, err
	}

	hostname := parsedURL.Host

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return CdnShareData{}, err
	}

	ip := ips[0]

	if data, ok := whoisCache[ip.String()]; ok {
		return CdnShareData{
			Timestamp:        time.Now(),
			CdnIp:            ip.String(),
			CustomerHostname: hostname,
			CdnOrgName:       prettyCdnOrgName(data.CdnOrgName),
			ParsedWhois:      data.ParsedWhois,
		}, nil
	}

	// Create a new client for the ipinfo package.
	client := ipinfo.NewClient(nil, nil, IPINFO_TOKEN)

	info, err := client.GetIPInfo(ip)
	if err != nil {
		return CdnShareData{}, err
	}

	cdnOrgName, _ := client.GetIPOrg(ip)
	prettyName := prettyCdnOrgName(cdnOrgName)

	whoisCache[ip.String()] = WhoisCacheData{
		Timestamp:   time.Now(),
		CdnOrgName:  prettyName,
		ParsedWhois: info.Org,
	}
	return CdnShareData{
		Timestamp:        time.Now(),
		CdnIp:            ip.String(),
		CustomerHostname: hostname,
		CdnOrgName:       prettyName,
		ParsedWhois:      info.Org,
	}, nil
}

func who2(u string, expectedFields []string) (CdnShareData, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return CdnShareData{}, err
	}

	hostname := parsedURL.Host

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return CdnShareData{}, err
	}

	ip := ips[0]

	if data, ok := whoisCache[ip.String()]; ok {
		return CdnShareData{
			Timestamp:        time.Now(),
			CdnIp:            ip.String(),
			CustomerHostname: hostname,
			CdnOrgName:       data.CdnOrgName,
			ParsedWhois:      data.ParsedWhois,
		}, nil
	}

	whoisResult, err := whois.Whois(ip.String())
	if err != nil {
		return CdnShareData{}, err
	}

	cdnOrgName := parseWhois(whoisResult, expectedFields)
	prettyName := prettyCdnOrgName(cdnOrgName)

	whoisCache[ip.String()] = WhoisCacheData{
		Timestamp:   time.Now(),
		CdnOrgName:  prettyName,
		ParsedWhois: whoisResult,
	}
	return CdnShareData{
		Timestamp:        time.Now(),
		CdnIp:            ip.String(),
		CustomerHostname: hostname,
		CdnOrgName:       prettyName,
		ParsedWhois:      whoisResult,
	}, nil
}

func parseWhois(whoisResult string, expectedFields []string) string {
	lines := strings.Split(whoisResult, "\n")
	for _, line := range lines {
		for _, field := range expectedFields {
			if strings.HasPrefix(line, field) {
				return strings.ReplaceAll(strings.TrimSpace(line[len(field):]), ":", "")
			}
		}
	}
	return ""
}

/**
func saveData(account Account, data CdnShareData) error {
	query := fmt.Sprintf(`INSERT INTO %s (timestamp, cdn_ip, customer_hostname, cdn_org_name, customer_stream_type, account_name, account_unit, account_id, whois) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, account.DBTableName)

	_, err := db.Exec(query, data.Timestamp, data.CdnIp, data.CustomerHostname, data.CdnOrgName, data.CustomerStreamType, data.AccountName, data.AccountUnit, data.AccountID, data.ParsedWhois)
	return err
}

**/

/**func saveData(account Account, data CdnShareData) error {
	query := fmt.Sprintf(`INSERT INTO %s (timestamp, cdn_ip, hostname, cdn_orgname, stream_type, account_name, account_unit, account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, account.DBTableName)

	_, err := db.Exec(query, data.Timestamp, data.CdnIp, data.CustomerHostname, data.CdnOrgName, data.CustomerStreamType, data.AccountName, data.AccountUnit, data.AccountID)
	return err
}**/

func saveData(account Account, data CdnShareData) error {
	// Ensure the table exists before trying to insert data.
	err := ensureTableExists(account.DBTableName)
	if err != nil {
		return fmt.Errorf("error ensuring table exists: %w", err)
	}

	query := fmt.Sprintf(`INSERT INTO %s (timestamp, cdn_ip, hostname, cdn_orgname, stream_type, account_name, account_unit, account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, account.DBTableName)

	_, err = db.Exec(query, data.Timestamp, data.CdnIp, data.CustomerHostname, data.CdnOrgName, data.CustomerStreamType, data.AccountName, data.AccountUnit, data.AccountID)
	return err
}

// New function to ensure the table exists.
func ensureTableExists(tableName string) error {
	// Check if the table exists.
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 
			FROM information_schema.tables 
			WHERE table_schema = ? AND table_name = ? AND TABLE_TYPE = 'BASE TABLE' AND ENGINE = 'MemSQL'
		)
	`
	err := db.QueryRow(query, config.Database.Database, tableName).Scan(&exists)
	if err != nil {
		return err
	}

	// If the table does not exist, create it.
	if !exists {
		_, err = db.Exec(fmt.Sprintf(`CREATE TABLE %s (
			"id" bigint(11) NOT NULL AUTO_INCREMENT,
			"timestamp" datetime DEFAULT NULL,
			"cdn_ip" text CHARACTER SET utf8 COLLATE utf8_general_ci,
			"hostname" varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
			"cdn_orgname" varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
			"stream_type" enum('live','ondemand') CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
			"account_name" varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
			"account_unit" varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
			"account_id" varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
			UNIQUE KEY "PRIMARY" ("id") USING HASH,
			SHARD KEY "__SHARDKEY" ("id"),
			KEY "__UNORDERED" () USING CLUSTERED COLUMNSTORE
		  ) AUTO_INCREMENT=1 AUTOSTATS_CARDINALITY_MODE=INCREMENTAL AUTOSTATS_HISTOGRAM_MODE=CREATE AUTOSTATS_SAMPLING=ON SQL_MODE='STRICT_ALL_TABLES'`, tableName))
	}

	return err
}

func loadCache() error {
	cacheData, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			// If the cache file does not exist yet, that's fine
			return nil
		}
		return err
	}

	dec := gob.NewDecoder(strings.NewReader(string(cacheData)))
	return dec.Decode(&whoisCache)
}

func saveCache() error {
	var b strings.Builder
	enc := gob.NewEncoder(&b)

	err := enc.Encode(whoisCache)
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFile, []byte(b.String()), 0666)
}

type PrettyNameMapping struct {
	Pattern    string
	PrettyName string
}

func prettyCdnOrgName(cdnOrgName string) string {
	for _, mapping := range cdnOrgNameMappings {
		if strings.Contains(cdnOrgName, mapping.Pattern) {
			return strings.TrimSpace(mapping.PrettyName)
		}
	}
	// If no pretty name is found, return the original cdnOrgName
	return strings.TrimSpace(cdnOrgName)
}
