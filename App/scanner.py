import nmap
def scan_target(target):

    # Simulated scan results for demo

    results = [
        {
            "ip": target,
            "port": 80,
            "service": "http",
            "vulnerability": "Outdated HTTP Server"
        },
        {
            "ip": target,
            "port": 22,
            "service": "ssh",
            "vulnerability": "Weak SSH Configuration"
        },
        {
            "ip": target,
            "port": 443,
            "service": "https",
            "vulnerability": "SSL Certificate Issue"
        },
        {
            "ip": target,
            "port": 3306,
            "service": "mysql",
            "vulnerability": "Database Exposure"
        }
    ]

    return results
