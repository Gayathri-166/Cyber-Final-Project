import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

def send_alert(vulns, target, total_risk):

    sender = "gayathrithalla28@gmail.com"
    password = "tmaqeoxautdfledd"
    receiver = "thallagayathri18@gmail.com"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 HIGH RISK ALERT - {target}"
    msg["From"] = sender
    msg["To"] = receiver

    html = f"""
    <h2>🚨 High/Critical Vulnerabilities Detected</h2>

    <p><b>Target:</b> {target}</p>
    <p><b>Scan Time:</b> {datetime.now()}</p>
    <p><b>Overall Risk Score:</b> {total_risk}</p>

    <table border="1">
    <tr>
        <th>Port</th>
        <th>Severity</th>
        <th>Risk</th>
        <th>Action</th>
    </tr>
    """

    for v in vulns:
        action = "Patch/update service immediately"

        html += f"""
        <tr>
            <td>{v['Port']}</td>
            <td>{v['Severity']}</td>
            <td>{v['Risk']}</td>
            <td>{action}</td>
        </tr>
        """

    html += """
    </table>
    <br>
    <p><i>This is an automated alert from your Cyber Risk Scanner.</i></p>
    """

    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())