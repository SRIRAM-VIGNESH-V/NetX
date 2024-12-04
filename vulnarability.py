
# Function to perform Nmap scan
def nmap_scan(ip_address):
    import nmap
    print(f"Scanning ip_address: {ip_address}")
    nm = nmap.PortScanner()

    try:
        # Perform the scan with vulners script for vulnerabilities
        nm.scan(ip_address, arguments='-sV --script vulners --script-args mincvss+5.0')
        
        # Show general scan information
        print("General Information about the scan:")
        print(f"Host: {ip_address}")
        
        # Accessing Nmap scan time from scanstats() safely
        scan_time = nm.scanstats().get('timestr', 'N/A')
        print(f"Scan Time: {scan_time}")
        
        # Accessing Nmap version safely
        nmap_version = nm.nmap_version()
        print(f"Nmap Version: {nmap_version}")
        
        # Accessing scan summary safely (handling case if it doesn't exist)
        scan_summary = nm.scanstats().get('summary', 'No summary available')
        print(f"Scan Summary: {scan_summary}")
        print("\n" + "="*50 + "\n")
        
        # Detailed Information about each open port
        print("Open Ports and Services:")
        for host in nm.all_hosts():
            print(f"Host {host} ({nm[host].hostname()}) is {nm[host].state()}")
            
            for protocol in nm[host].all_protocols():
                print(f"Protocol: {protocol}")
                lport = nm[host][protocol].keys()
                for port in lport:
                    print(f"Port: {port}, Service: {nm[host][protocol][port]['name']}")
                    print(f"Product: {nm[host][protocol][port].get('product', 'N/A')}")
                    print(f"Version: {nm[host][protocol][port].get('version', 'N/A')}")
                    print(f"State: {nm[host][protocol][port]['state']}")
                    print("-"*40)

        # Vulnerabilities Information
        print("\n" + "="*50 + "\n")
        print("Vulnerabilities Information:")
        for host in nm.all_hosts():
            print(f"Scanning Host: {host}")
            if 'script' in nm[host]:
                if 'vulners' in nm[host]['script']:
                    vulns = nm[host]['script']['vulners']
                    for vuln in vulns:
                        print(f"\nVulnerability: {vuln}")
                        print(f"CVSS Score: {vulns[vuln].get('cvss', 'N/A')}")
                        print(f"Description: {vulns[vuln].get('description', 'No description available')}")
                        print(f"References: {vulns[vuln].get('references', 'N/A')}")
                        
                        # Adding common mitigation suggestions
                        if "CVE" in vuln:
                            cve_id = vuln.split(":")[1]
                            print(f"Suggested Mitigation for {cve_id}:")
                            print(f"  - Check for available patches or updates related to {cve_id}")
                            print(f"  - Review the system configuration to minimize exposure")
                            print(f"  - Apply the latest security updates from the vendor")
                            print(f"  - Refer to official CVE details: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
                        
                        print("-"*40)
                else:
                    print("No vulnerabilities detected on this host.")
            else:
                print("No script data available.")
        
        # Common Security Suggestions for Open Ports
        print("\n" + "="*50 + "\n")
        print("Common Security Suggestions:")
        for host in nm.all_hosts():
            if 'hostnames' in nm[host]:
                print(f"\nHost {host} ({nm[host].hostname()}):")
                if 80 in nm[host]['tcp']:
                    print(f"Port 80 (HTTP) is open.")
                    print(f"- Suggestion: Ensure the HTTP service (nginx) is up-to-date.")
                    print(f"- Common CVEs: CVE-2021-22965, CVE-2019-11043.")
                    print(f"- Mitigation: Update nginx, review configurations.")
                    print(f"- Disable unused HTTP methods (e.g., TRACE, OPTIONS).")
                    print(f"- Implement security headers: X-Content-Type-Options, X-Frame-Options.")
                if 443 in nm[host]['tcp']:
                    print(f"Port 443 (HTTPS) is open.")
                    print(f"- Suggestion: Ensure strong SSL/TLS settings.")
                    print(f"- Common CVEs: CVE-2021-22965, CVE-2019-11043.")
                    print(f"- Mitigation: Use SSL Labs' test, configure HSTS, disable weak ciphers.")
                    print(f"- Enable Perfect Forward Secrecy (PFS) in the SSL configuration.")
                    print(f"- Ensure the use of strong SSL/TLS protocols (TLS 1.2 and TLS 1.3).")
                if 22 in nm[host]['tcp']:
                    print(f"Port 22 (SSH) is open.")
                    print(f"- Suggestion: Disable root login via SSH.")
                    print(f"- Mitigation: Use SSH keys for authentication, disable password-based logins.")
                    print(f"- Ensure the latest OpenSSH version is installed.")
        
        # OS and Software Version Specific Suggestions
        print("\n" + "="*50 + "\n")
        print("OS & Version Specific Suggestions:")
        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            if 'osmatch' in nm[host]:
                for os_info in nm[host]['osmatch']:
                    print(f"OS: {os_info.get('osclass', 'Unknown')} Version: {os_info.get('osfamily', 'Unknown')}")
                    print(f"Suggested Mitigation for {os_info.get('osfamily', 'Unknown')} OS:")
                    print(f"  - Regularly update the OS with security patches.")
                    print(f"  - Disable unnecessary services to reduce the attack surface.")
                    print(f"  - Implement security configurations specific to the OS (e.g., AppArmor, SELinux).")

                    # Example specific to Ubuntu or Linux OS
                    if "Ubuntu" in os_info.get('osclass', ''):
                        print(f"  - Ensure that all packages are up-to-date using `sudo apt update && sudo apt upgrade`.")
                    if "Windows" in os_info.get('osclass', ''):
                        print(f"  - Enable Windows Defender and ensure the latest antivirus definitions are in place.")
                        print(f"  - Review the Windows Security Center for best practices.")
                        print(f"  - Enforce group policy to restrict access to critical files.")
                        print(f"  - Enable BitLocker encryption for Windows devices.")
                        print(f"  - Use Windows Sandbox for risky software installations.")
                    if "Red Hat" in os_info.get('osclass', ''):
                        print(f"  - Use `yum` or `dnf` for automated patching and upgrading of packages.")
                        print(f"  - Disable unnecessary services like FTP, Samba, Telnet, etc.")
        
        # Large Scale Recommendations for Specific Software
        print("\n" + "="*50 + "\n")
        print("Large Scale Recommendations for Specific Software:")
        for host in nm.all_hosts():
            if 80 in nm[host]['tcp']:
                print(f"HTTP Service detected (Port 80) - Product: {nm[host]['tcp'][80].get('product', 'N/A')}")
                if 'nginx' in nm[host]['tcp'][80].get('product', ''):
                    print(f"  - Update nginx to the latest stable release.")
                    print(f"  - CVE-2019-11043: Ensure proper handling of HTTP/2 requests.")
                    print(f"  - CVE-2020-5551: Ensure proper access control for web services.")
                    print(f"  - Disable HTTP TRACE method.")
                    print(f"  - Configure `nginx.conf` to secure the web application.")
                    print(f"  - Set `http_only` flags for session cookies.")
        
        # Firewall Configuration and Best Practices
        print("\n" + "="*50 + "\n")
        print("Firewall Configuration and Best Practices:")
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                print(f"\nHost {host} firewall configuration suggestions:")
                print(f"  - Ensure that only necessary ports are open (e.g., 80, 443, 22).")
                print(f"  - Block all inbound traffic by default and only allow specific IPs.")
                print(f"  - Use Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) like Snort.")
                print(f"  - Enable logging to track suspicious activity.")
        
        print("\nScan Completed.")

    except Exception as e:
        print(f"Error during scan: {str(e)}")

