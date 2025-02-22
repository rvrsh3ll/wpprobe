![WPProbe](./images/logo.jpg)

**"Because why scan blind when WordPress exposes itself?"**  

---

![WPProbe](./images/wpprobe.png)

[![Go CI](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml)
[![Latest Release](https://img.shields.io/github/v/release/Chocapikk/wpprobe)](https://github.com/Chocapikk/wpprobe/releases/latest)


## 🧐 What is WPProbe?  

**WPProbe** is a **fast and efficient WordPress plugin scanner** that leverages **REST API enumeration (`?rest_route`)** to detect installed plugins **without brute-force**.  

Unlike traditional scanners that hammer websites with requests, WPProbe takes a smarter approach by querying the exposed REST API. This technique allows us to **identify plugins stealthily**, reducing detection risks and **speeding up the scan process**.  

📌 **Currently, over 2200 plugins** can be identified using this method!  

---

## 🚀 How It Works  

1️⃣ **Fetch** a list of known WordPress plugins from a precompiled database (Wordfence).  
2️⃣ **Scan** the target site for exposed REST API routes (`?rest_route=/`).  
3️⃣ **Match** the discovered endpoints with known plugin signatures.  
4️⃣ **Retrieve** the installed version (when possible) by extracting metadata from files like `readme.txt`.  
5️⃣ **Correlate** detected plugins with publicly known vulnerabilities (CVE mapping).  
6️⃣ **Output** the results in a structured format (CSV or JSON) for easy analysis.  

🔥 **This means fewer requests, faster scans, and a lower chance of getting blocked by WAFs or security plugins!**  

---

## ⚙️ Features  

✅ **Stealthy detection** – No need to brute-force plugins; just ask WordPress nicely.  
✅ **High-speed scanning** – Multithreaded scanning with a sleek progress bar.  
✅ **Vulnerability mapping** – Automatically associates detected plugins with known CVEs.  
✅ **Multiple output formats** – Save results in **CSV** or **JSON**.  
✅ **Resilient scanning** – Handles sites with missing version info gracefully.  

---

## 📌 Limitations  

🔹 Some plugins don’t expose REST API endpoints, making them undetectable via this method.  
🔹 If a plugin is outdated, disabled, or hidden by security plugins, it may not be detected.  
🔹 The technique relies on a predefined plugin-to-endpoint mapping, which is regularly updated.  

---

## 🔧 Installation

### Option 1️⃣ (Quick setup via `go install`)

```bash
go install github.com/Chocapikk/wpprobe@latest
```
- **Requires Go 1.22+**  
- Ensure `$(go env GOPATH)/bin` is in your `$PATH`  

### Option 2️⃣ (Manual build)

1. **Clone the repository**  
   ```bash
   git clone https://github.com/Chocapikk/wpprobe
   cd wpprobe
   ```
2. **Install dependencies**  
   ```bash
   go mod tidy
   ```
3. **Build the binary**  
   ```bash
   go build -o wpprobe
   ```
   Move or copy `wpprobe` into a directory listed in your `$PATH`.

### Option 3️⃣ (Docker)
1. **Build Image**
   ```bash
   docker build -t wpprobe .
   ```
2. **Run**
   ```bash
   docker run -it --rm wpprobe
   ```

---

## 🕵️ Usage  

### **🔄 Update WPProbe**  
Update WPProbe to the latest version:  
```bash
./wpprobe update
```

### **Update the Wordfence database**  
Update the local Wordfence vulnerability database:  
```bash
./wpprobe update-db
```

### **Basic scan for a single website**  
Scan a single WordPress site:  
```bash
./wpprobe scan -u https://example.com
```

### **Scan multiple targets from a file with 20 concurrent threads**  
Scan multiple sites from a `targets.txt` file using 20 threads:  
```bash
./wpprobe scan -f targets.txt -t 20
```

### **Save results to a CSV file**  
Save scan results to a CSV file:  
```bash
./wpprobe scan -f targets.txt -t 20 -o results.csv
```

**Save results to a JSON File**  
Save scan results to a JSON file:  
```bash
./wpprobe scan -f targets.txt -t 20 -o results.json
```

---

## 📜 Example Output  

### **CSV Format**  

```
URL,Plugin,Version,Severity,AuthType,CVEs,Title
http://localhost:5555,give,2.20.1,critical,Unauth,CVE-2025-22777,Critical Unauthenticated PHP Object Injection
http://localhost:5555,give,2.20.1,critical,Unauth,CVE-2024-9634,PHP Object Injection to Remote Code Execution
http://localhost:5555,give,2.20.1,high,Unauth,CVE-2023-22719,Unauthenticated CSV Injection
http://localhost:5555,give,2.20.1,medium,Auth,CVE-2024-1957,Stored Cross-Site Scripting via Shortcode
http://localhost:5555,give,2.20.1,medium,Unknown,CVE-2023-25450,Cross-Site Request Forgery via give_cache_flush
http://localhost:5555,jetpack,14.3,None,N/A,,No vulnerabilities found
http://localhost:5555,io-plus,2.0.4,None,N/A,,No vulnerabilities found
http://localhost:5555,woocommerce,9.6.0,None,N/A,,No vulnerabilities found
```

### **JSON Format**  

```json
{
  "url": "http://localhost:5555",
  "plugins": {
    "give": [
      {
        "version": "2.20.1",
        "severities": {
          "critical": [
            {
              "authType": "Unauth",
              "cves": ["CVE-2025-22777", "CVE-2024-9634"]
            }
          ],
          "medium": [
            {
              "authType": "Auth",
              "cves": ["CVE-2024-1957", "CVE-2022-40211"]
            }
          ]
        }
      }
    ],
    "woocommerce": [
      {
        "version": "9.6.0",
        "severities": {
          "None": []
        }
      }
    ]
  }
}
```

---

## 🎯 Why WPProbe?  

💡 **The idea behind WPProbe** comes from the realization that **WordPress exposes plugin data through its REST API (`?rest_route`)**. Instead of wasting time brute-forcing plugin paths, this tool **matches REST endpoints with known plugin signatures**, allowing for faster and more stealthy scans.  

**Over 2200 plugins** are currently detectable using this method, making WPProbe one of the most effective tools for WordPress reconnaissance.  

---

## 🤖 Future Improvements  

🛠️ **Expanding the plugin database** – More plugins, better detection.  
⚡ **Adding more fingerprinting techniques** – Beyond REST API, integrating alternative detection methods.  
📊 **Enhanced reporting** – JSON output and integration with security dashboards.  

---

## ✨ Credits  

Developed by **@Chocapikk** 🍫, inspired by modern recon methodologies and the **REST API enumeration trick**.  

👀 Stay stealthy, scan smart! 🚀
