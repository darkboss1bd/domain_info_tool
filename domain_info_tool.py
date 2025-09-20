import socket
import ssl
import json
import urllib.request
import urllib.error
import webbrowser
import os
import re
from datetime import datetime
from urllib.parse import urlparse

class DomainInfoTool:
    def __init__(self):
        self.results = {}
        
    def get_whois_info(self, domain):
        """Get WHOIS information using socket connection to WHOIS server"""
        try:
            # Try common WHOIS servers
            whois_servers = [
                "whois.iana.org",
                "whois.internic.net",
                "whois.verisign-grs.com"
            ]
            
            whois_info = ""
            for server in whois_servers:
                try:
                    with socket.create_connection((server, 43)) as sock:
                        sock.send((domain + "\r\n").encode())
                        response = b""
                        while True:
                            data = sock.recv(1024)
                            if not data:
                                break
                            response += data
                    whois_info = response.decode()
                    if "not found" not in whois_info.lower():
                        break
                except:
                    continue
            
            return whois_info if whois_info else "WHOIS information not available"
        except Exception as e:
            return f"Error retrieving WHOIS info: {str(e)}"
    
    def get_dns_info(self, domain):
        """Get DNS records using socket"""
        dns_records = {}
        
        # Get A records (IPv4)
        try:
            a_records = socket.gethostbyname_ex(domain)
            dns_records['A'] = a_records[2]
        except:
            dns_records['A'] = "No record found"
        
        # Get MX records (try via DNS query)
        try:
            # This is a simple approach that may not work for all domains
            # In a real implementation, you'd use a proper DNS library
            dns_records['MX'] = "MX records require dnspython library"
        except:
            dns_records['MX'] = "No record found"
        
        # Get NS records
        try:
            # Again, simplified approach
            dns_records['NS'] = "NS records require dnspython library"
        except:
            dns_records['NS'] = "No record found"
        
        return dns_records
    
    def get_ssl_info(self, domain):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            ssl_info = {
                'issuer': dict(x[0] for x in cert['issuer']),
                'subject': dict(x[0] for x in cert['subject']),
                'version': cert.get('version', 'N/A'),
                'notBefore': cert.get('notBefore', 'N/A'),
                'notAfter': cert.get('notAfter', 'N/A'),
            }
            return ssl_info
        except Exception as e:
            return f"Error retrieving SSL info: {str(e)}"
    
    def get_http_headers(self, domain):
        """Get HTTP headers"""
        try:
            # Try HTTPS first
            req = urllib.request.Request(f"https://{domain}")
            with urllib.request.urlopen(req, timeout=10) as response:
                return dict(response.headers)
        except urllib.error.URLError:
            try:
                # Fall back to HTTP
                req = urllib.request.Request(f"http://{domain}")
                with urllib.request.urlopen(req, timeout=10) as response:
                    return dict(response.headers)
            except Exception as e:
                return f"Error retrieving HTTP headers: {str(e)}"
        except Exception as e:
            return f"Error retrieving HTTP headers: {str(e)}"
    
    def get_server_info(self, headers):
        """Extract server information from headers"""
        server_info = {}
        if isinstance(headers, dict):
            server_info['server'] = headers.get('Server', 'Not found')
            server_info['x-powered-by'] = headers.get('X-Powered-By', 'Not found')
        return server_info
    
    def get_ip_info(self, domain):
        """Get IP address information"""
        try:
            ip_address = socket.gethostbyname(domain)
            # Get IP location using free API
            try:
                with urllib.request.urlopen(f"http://ip-api.com/json/{ip_address}", timeout=10) as response:
                    ip_info = json.loads(response.read().decode())
                return ip_address, ip_info
            except:
                return ip_address, {"error": "Could not retrieve IP details"}
        except Exception as e:
            return None, f"Error retrieving IP info: {str(e)}"
    
    def capture_all_info(self, domain):
        """Capture all domain information"""
        print(f"[+] Gathering information for {domain}...")
        
        self.results['domain'] = domain
        self.results['scan_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # WHOIS Information
        print("[+] Getting WHOIS information...")
        self.results['whois'] = self.get_whois_info(domain)
        
        # DNS Information
        print("[+] Getting DNS records...")
        self.results['dns'] = self.get_dns_info(domain)
        
        # SSL Information
        print("[+] Getting SSL certificate info...")
        self.results['ssl'] = self.get_ssl_info(domain)
        
        # HTTP Headers
        print("[+] Getting HTTP headers...")
        self.results['headers'] = self.get_http_headers(domain)
        
        # Server Information
        print("[+] Getting server info...")
        self.results['server'] = self.get_server_info(self.results['headers'])
        
        # IP Information
        print("[+] Getting IP information...")
        self.results['ip_address'], self.results['ip_info'] = self.get_ip_info(domain)
        
        print("[+] Information gathering complete!")
        return self.results
    
    def generate_html_report(self, output_file="domain_report.html"):
        """Generate a stylish HTML report with the collected information"""
        print(f"[+] Generating HTML report: {output_file}")
        
        # HTML template with hacker theme and branding
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Domain Information Report - darkboss1bd</title>
            <style>
                body {{
                    font-family: 'Courier New', monospace;
                    background-color: #0a0a0a;
                    color: #00ff00;
                    margin: 0;
                    padding: 20px;
                    background-image: radial-gradient(circle, #111111 0%, #000000 100%);
                    background-size: 100% 100%;
                    background-attachment: fixed;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: rgba(10, 10, 10, 0.9);
                    border: 1px solid #00ff00;
                    border-radius: 5px;
                    padding: 20px;
                    box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
                    position: relative;
                    overflow: hidden;
                }}
                
                .container::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background-image: 
                        linear-gradient(rgba(0, 255, 0, 0.1) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(0, 255, 0, 0.1) 1px, transparent 1px);
                    background-size: 20px 20px;
                    z-index: -1;
                    opacity: 0.3;
                }}
                
                .header {{
                    text-align: center;
                    padding: 20px;
                    border-bottom: 1px solid #00ff00;
                    margin-bottom: 30px;
                    position: relative;
                }}
                
                .brand {{
                    font-size: 28px;
                    font-weight: bold;
                    color: #00ff00;
                    text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
                    margin-bottom: 10px;
                    letter-spacing: 2px;
                }}
                
                .domain {{
                    font-size: 24px;
                    color: #ffffff;
                    margin-bottom: 10px;
                    text-shadow: 0 0 5px rgba(255, 255, 255, 0.5);
                }}
                
                .scan-date {{
                    font-size: 14px;
                    color: #888;
                }}
                
                .section {{
                    margin-bottom: 30px;
                    padding: 15px;
                    border: 1px solid #333;
                    border-radius: 5px;
                    background-color: rgba(20, 20, 20, 0.8);
                    position: relative;
                    overflow: hidden;
                }}
                
                .section::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 2px;
                    background: linear-gradient(90deg, #00ff00, transparent);
                    animation: scanline 3s linear infinite;
                }}
                
                @keyframes scanline {{
                    0% {{ transform: translateX(-100%); }}
                    100% {{ transform: translateX(100%); }}
                }}
                
                .section-title {{
                    font-size: 20px;
                    color: #00ff00;
                    margin-bottom: 15px;
                    padding-bottom: 5px;
                    border-bottom: 1px solid #333;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}
                
                .info-table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                
                .info-table th, .info-table td {{
                    padding: 8px 12px;
                    text-align: left;
                    border: 1px solid #333;
                }}
                
                .info-table th {{
                    background-color: #111;
                    color: #00ff00;
                    font-weight: bold;
                }}
                
                .info-table tr:nth-child(even) {{
                    background-color: rgba(30, 30, 30, 0.5);
                }}
                
                .info-table tr:hover {{
                    background-color: rgba(0, 255, 0, 0.1);
                }}
                
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #333;
                    font-size: 12px;
                    color: #666;
                }}
                
                .links {{
                    display: flex;
                    justify-content: center;
                    gap: 20px;
                    margin-bottom: 10px;
                }}
                
                .links a {{
                    color: #00ff00;
                    text-decoration: none;
                    padding: 5px 10px;
                    border: 1px solid #00ff00;
                    border-radius: 3px;
                    transition: all 0.3s ease;
                }}
                
                .links a:hover {{
                    background-color: #00ff00;
                    color: #000;
                    text-shadow: 0 0 5px rgba(0, 0, 0, 0.5);
                    box-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
                }}
                
                pre {{
                    background-color: #111;
                    padding: 10px;
                    border-radius: 5px;
                    overflow-x: auto;
                    color: #00ff00;
                    border: 1px solid #333;
                    font-family: 'Courier New', monospace;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                
                .json-key {{
                    color: #ffa500;
                }}
                
                .json-string {{
                    color: #00ffff;
                }}
                
                .json-number {{
                    color: #ff00ff;
                }}
                
                .json-boolean {{
                    color: #00ff00;
                }}
                
                .pulse {{
                    animation: pulse 2s infinite;
                }}
                
                @keyframes pulse {{
                    0% {{ opacity: 0.7; }}
                    50% {{ opacity: 1; }}
                    100% {{ opacity: 0.7; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="brand">darkboss1bd</div>
                    <div class="domain">Domain Information Report</div>
                    <div class="scan-date">Scan performed on: {self.results.get('scan_date', 'N/A')}</div>
                </div>
                
                <div class="section">
                    <div class="section-title">Target Domain</div>
                    <table class="info-table">
                        <tr>
                            <th>Domain Name</th>
                            <td>{self.results.get('domain', 'N/A')}</td>
                        </tr>
                        <tr>
                            <th>IP Address</th>
                            <td>{self.results.get('ip_address', 'N/A')}</td>
                        </tr>
                    </table>
                </div>
        """
        
        # WHOIS Information Section
        whois_info = self.results.get('whois', '')
        html_template += """
                <div class="section">
                    <div class="section-title">WHOIS Information</div>
                    <pre>
        """
        
        html_template += whois_info if whois_info else "WHOIS information not available"
        
        html_template += """
                    </pre>
                </div>
        """
        
        # DNS Information Section
        dns_info = self.results.get('dns', {})
        html_template += """
                <div class="section">
                    <div class="section-title">DNS Records</div>
                    <table class="info-table">
                        <tr>
                            <th>Record Type</th>
                            <th>Value</th>
                        </tr>
        """
        
        for record_type, values in dns_info.items():
            if isinstance(values, list):
                display_value = '<br>'.join(values)
            else:
                display_value = values
                
            html_template += f"""
                        <tr>
                            <td>{record_type}</td>
                            <td>{display_value}</td>
                        </tr>
            """
        
        html_template += """
                    </table>
                </div>
        """
        
        # SSL Information Section
        ssl_info = self.results.get('ssl', {})
        html_template += """
                <div class="section">
                    <div class="section-title">SSL Certificate Information</div>
        """
        
        if isinstance(ssl_info, dict):
            html_template += """
                    <table class="info-table">
            """
            
            ssl_fields = [
                ('Issuer', ssl_info.get('issuer', {}).get('organizationName', 'N/A')),
                ('Subject', ssl_info.get('subject', {}).get('commonName', 'N/A')),
                ('Valid From', ssl_info.get('notBefore', 'N/A')),
                ('Valid Until', ssl_info.get('notAfter', 'N/A')),
                ('Version', ssl_info.get('version', 'N/A')),
            ]
            
            for field_name, field_value in ssl_fields:
                html_template += f"""
                        <tr>
                            <th>{field_name}</th>
                            <td>{field_value}</td>
                        </tr>
                """
            
            html_template += """
                    </table>
            """
        else:
            html_template += f"""
                    <p>{ssl_info}</p>
            """
        
        html_template += """
                </div>
        """
        
        # Server Information Section
        server_info = self.results.get('server', {})
        html_template += """
                <div class="section">
                    <div class="section-title">Server Information</div>
                    <table class="info-table">
        """
        
        for key, value in server_info.items():
            html_template += f"""
                        <tr>
                            <th>{key}</th>
                            <td>{value}</td>
                        </tr>
            """
        
        html_template += """
                    </table>
                </div>
        """
        
        # IP Information Section
        ip_info = self.results.get('ip_info', {})
        html_template += """
                <div class="section">
                    <div class="section-title">IP Information</div>
        """
        
        if isinstance(ip_info, dict) and 'error' not in ip_info:
            html_template += """
                    <table class="info-table">
            """
            
            ip_fields = [
                ('IP Address', self.results.get('ip_address', 'N/A')),
                ('Country', ip_info.get('country', 'N/A')),
                ('Region', ip_info.get('regionName', 'N/A')),
                ('City', ip_info.get('city', 'N/A')),
                ('ISP', ip_info.get('isp', 'N/A')),
                ('Organization', ip_info.get('org', 'N/A')),
                ('AS Number', ip_info.get('as', 'N/A')),
                ('Timezone', ip_info.get('timezone', 'N/A')),
                ('Coordinates', f"{ip_info.get('lat', 'N/A')}, {ip_info.get('lon', 'N/A')}"),
            ]
            
            for field_name, field_value in ip_fields:
                html_template += f"""
                        <tr>
                            <th>{field_name}</th>
                            <td>{field_value}</td>
                        </tr>
                """
            
            html_template += """
                    </table>
            """
        else:
            html_template += f"""
                    <p>{ip_info.get('error', 'IP information not available')}</p>
            """
        
        html_template += """
                </div>
                
                <div class="footer">
                    <div class="links">
                        <a href="https://t.me/darkvaiadmin" target="_blank">Telegram ID</a>
                        <a href="https://serialkey.top/" target="_blank">My Website</a>
                        <a href="https://t.me/windowspremiumkey" target="_blank">Telegram Channel</a>
                    </div>
                    <div>Report generated by darkboss1bd Domain Information Tool</div>
                </div>
            </div>
            
            <script>
                // Simple syntax highlighting for JSON data
                function syntaxHighlight(json) {{
                    if (typeof json != 'string') {{
                        json = JSON.stringify(json, undefined, 2);
                    }}
                    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                    return json.replace(/("(\\\\u[a-zA-Z0-9]{{4}}|\\\\[^u]|[^\\\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, 
                    function (match) {{
                        var cls = 'json-number';
                        if (/^"/.test(match)) {{
                            if (/:$/.test(match)) {{
                                cls = 'json-key';
                            }} else {{
                                cls = 'json-string';
                            }}
                        }} else if (/true|false/.test(match)) {{
                            cls = 'json-boolean';
                        }} else if (/null/.test(match)) {{
                            cls = 'json-null';
                        }}
                        return '<span class="' + cls + '">' + match + '</span>';
                    }});
                }}
                
                // Apply syntax highlighting to all pre elements
                document.addEventListener('DOMContentLoaded', function() {{
                    var preElements = document.querySelectorAll('pre');
                    preElements.forEach(function(pre) {{
                        pre.innerHTML = syntaxHighlight(pre.textContent);
                    }});
                }});
            </script>
        </body>
        </html>
        """
        
        # Write the HTML report to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return output_file

def main():
    """Main function to run the domain information tool"""
    print("""
    #############################################
    #          darkboss1bd Domain Tool          #
    #         Telegram: @darkvaiadmin           #
    #        Website: https://serialkey.top/    #
    #############################################
    """)
    
    # Get domain from user
    domain = input("Enter the domain to analyze (without http/https): ").strip()
    
    if not domain:
        print("Error: No domain provided!")
        return
    
    # Create tool instance
    tool = DomainInfoTool()
    
    # Capture all information
    results = tool.capture_all_info(domain)
    
    # Generate HTML report
    output_file = f"{domain}_report.html"
    report_path = tool.generate_html_report(output_file)
    
    print(f"[+] Report saved as: {report_path}")
    
    # Automatically open the report in the default browser
    print("[+] Opening report in browser...")
    webbrowser.open(f"file://{os.path.abspath(report_path)}")
    
    print("\n[+] Process completed successfully!")

if __name__ == "__main__":
    main()
