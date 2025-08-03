# Sample SSL Certificate Check
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999003");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("SSL Certificate Expiry Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("SSL and TLS");
  script_dependencies("ssl_cert_details.nasl");
  script_require_ports("Services/www", 443);
  script_tag(name:"summary", value:"Checks SSL certificate expiry.");
  script_tag(name:"insight", value:"SSL certificates should be renewed before expiry.");
  script_tag(name:"solution", value:"Renew SSL certificate before expiry date.");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

port = get_service(svc:"www", default:443, exit_on_fail:TRUE);
cert = get_server_cert(port:port);

if(cert) {
  expiry = cert_query(cert, "not-after");
  if(expiry) {
    days_left = (expiry - unixtime()) / 86400;
    if(days_left < 30) {
      security_message(port:port, data:"SSL certificate expires in " + days_left + " days");
    }
  }
}
