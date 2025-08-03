# Sample Apache Server Info
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999004");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache Server Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"Checks for Apache server information disclosure.");
  script_tag(name:"insight", value:"Apache server may reveal version information.");
  script_tag(name:"solution", value:"Configure ServerTokens to Prod in Apache configuration.");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if(banner && "Apache" >< banner) {
  if(egrep(pattern:"Server: Apache/[0-9.]+", string:banner)) {
    security_message(port:port, data:"Apache server version information disclosed in banner");
  }
}
