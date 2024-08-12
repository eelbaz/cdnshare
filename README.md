# CDN Data Collection Tool

This application is used for collecting data about content delivery networks (CDNs). The program collects streaming URLs from specified accounts, logging into the streaming service via `chromedp`  listening on the client's network events via chrome developer tools protocol (cdp), and extracts the CDN's organization name, and other useful network level details, using the `whois` protocol. The extracted data is then saved in a MySQL database for later use in share and workflow analysis.

## Getting Started

### Prerequisites

1. [Go (version 1.16 or later)](https://golang.org/dl/)

2. [MySQL](https://dev.mysql.com/downloads/mysql/)

3. [chromedp](https://github.com/chromedp/chromedp)

4. [whois](https://github.com/likexian/whois)

5. [go-sql-driver](https://github.com/go-sql-driver/mysql)

### Configuration

The `config.json` file is used to configure database credentials, maximum connections, and the accounts from which the streaming URLs will be collected. Each account should have an associated sleep duration and database table name.

An example `config.json` structure is shown below:

```json
{
  "database": {
    "host": "localhost",
    "port": "3306",
    "database": "cdn_data",
    "user": "root",
    "password": "password",
    "maxOpenConns": 100,
    "maxIdleConns": 10
  },
  "accounts": [
    {
      "name": "Account 1",
      "unit": "Unit 1",
      "id": "Account ID 1",
      "urls": {
        "live": "http://live.example-streaming-service.com",
        "ondemand": "http://ondemand.example-streaming-service.com"
      },
      "mediaTypeFilters": [".ts", ".mp4",".m4s",".mpd",".m3u8"],
      "sleepDuration": 10,
      "db_table_name": "cdn_data_account1"
    }
  ]
}
```

### Usage

Initialize all of the dependencies: 
```
go mod init
go mod tidy
```

To run the application, use the `go run` command followed by the name of the file.

```bash
go run main.go
```
```

The application will start collecting the streaming URLs and saving the extracted data to the specified MySQL database.

### Understanding the Code

The application works in the following steps:

1. Reads the `config.json` file and establishes a connection with the MySQL database.

2. Loads any whois cache data from the `whois_cache.gob` file  from previous runs if it exists. This is intended to avoid spamming/abusing the whois look up db.

3. For each account in the config, it navigates to the URLs and listens for network events.

4. When a request is sent from the browser, it filters the request by the specified media types, gets the CDN IP address, performs a `whois` lookup, and stores the CDN organization name, the stream type, and account information in the database.

5. Repeats the above steps after a sleep duration specified for each account.

6. Finally, it saves the cache data to the `whois_cache.gob` file for future use.

### Customization

You can customize the application by adding more pretty name mappings in the `cdnOrgNameMappings` variable and adding more account details in the `config.json` file.

### Note

Please make sure that you have necessary permissions , and are in compliance with a services terms of use.
